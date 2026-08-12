use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{config, registry, workspace};

#[derive(Debug, Clone, Default)]
pub struct TargetSelector {
    pub project: Option<String>,
    pub app: Option<String>,
    pub all: bool,
}

impl TargetSelector {
    pub fn one(project: Option<String>, app: Option<String>) -> Self {
        Self {
            project,
            app,
            all: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceTarget {
    pub name: String,
    pub path: PathBuf,
    pub vault: PathBuf,
    pub workspace_root: Option<PathBuf>,
    pub workspace_name: Option<String>,
    pub app_slug: Option<String>,
    pub package_name: Option<String>,
}

impl WorkspaceTarget {
    pub fn resolved_project(&self) -> registry::ResolvedProject {
        registry::ResolvedProject {
            name: self.name.clone(),
            path: self.path.clone(),
            vault: self.vault.clone(),
        }
    }

    pub fn is_workspace_child(&self) -> bool {
        self.workspace_root.is_some()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExecutionPlanOptions {
    pub profile_command: bool,
}

#[derive(Debug, Clone)]
pub struct WorkspaceExecutionPlan {
    pub workspace_root: Option<PathBuf>,
    pub app_path: PathBuf,
    pub app_relative_path: Option<PathBuf>,
    pub app_slug: Option<String>,
    pub package_name: Option<String>,
    pub package_scripts: Vec<String>,
    pub project: String,
    pub vault: PathBuf,
    pub execution_cwd: PathBuf,
    pub workspace_package_manager: Option<String>,
    pub target: WorkspaceTarget,
}

impl WorkspaceExecutionPlan {
    pub fn resolved_project(&self) -> registry::ResolvedProject {
        self.target.resolved_project()
    }

    pub fn is_workspace_app(&self) -> bool {
        self.workspace_root.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedCommand {
    pub argv: Vec<String>,
    pub display: String,
    pub mounted: bool,
}

pub fn resolve_one(selector: &TargetSelector, cwd: &Path) -> Result<WorkspaceTarget> {
    if selector.all {
        anyhow::bail!("--all cannot be used where exactly one Ward project is required");
    }
    if selector.project.is_some() && selector.app.is_some() {
        anyhow::bail!("choose either --project or --app, not both");
    }
    if let Some(project) = selector.project.as_deref() {
        return explicit_project(project, cwd);
    }
    if let Some(app) = selector.app.as_deref() {
        return explicit_app(app, cwd);
    }
    implicit_one(cwd)
}

pub fn resolve_execution_plan(
    selector: &TargetSelector,
    cwd: &Path,
    options: ExecutionPlanOptions,
) -> Result<WorkspaceExecutionPlan> {
    let mut target = resolve_one(selector, cwd)?;
    let mut workspace_package_manager = None;
    let mut package_scripts = Vec::new();
    if target.workspace_root.is_some() || workspace::discover_containing(&target.path)?.is_some() {
        attach_workspace_metadata(&mut target)?;
    }

    let mut workspace_root = target.workspace_root.clone();
    let mut app_relative_path = None;
    if let Some(root) = workspace_root.as_deref() {
        let discovery = workspace::discover(root)?;
        if let Some(discovery) = discovery {
            workspace_package_manager = discovery.package_manager.clone();
            if let Some(package) = find_workspace_package_for_target(&discovery, &target) {
                workspace_root = Some(discovery.root.clone());
                app_relative_path = Some(package.relative_path.clone());
                package_scripts = package.scripts.clone();
                target.workspace_root = Some(discovery.root.clone());
                target.workspace_name = Some(discovery.workspace_name.clone());
                target.app_slug = Some(package.slug.clone());
                target.package_name = package.name.clone();
            }
        }
    }

    if app_relative_path.is_none() {
        if let Some(root) = workspace_root.as_deref() {
            app_relative_path = relative_path(root, &target.path);
        }
    }

    let execution_cwd = if let Some(root) = workspace_root.as_ref() {
        root.clone()
    } else if selector.project.is_some() && options.profile_command {
        target.path.clone()
    } else {
        cwd.to_path_buf()
    };

    Ok(WorkspaceExecutionPlan {
        workspace_root,
        app_path: target.path.clone(),
        app_relative_path,
        app_slug: target.app_slug.clone(),
        package_name: target.package_name.clone(),
        package_scripts,
        project: target.name.clone(),
        vault: target.vault.clone(),
        execution_cwd,
        workspace_package_manager,
        target,
    })
}

pub fn mount_command(plan: &WorkspaceExecutionPlan, argv: &[String]) -> Result<MountedCommand> {
    mount_command_inner(plan, argv, true)
}

pub fn mount_profile_command(
    plan: &WorkspaceExecutionPlan,
    argv: &[String],
) -> Result<MountedCommand> {
    mount_command_inner(plan, argv, false)
}

fn mount_command_inner(
    plan: &WorkspaceExecutionPlan,
    argv: &[String],
    reject_unsupported_raw: bool,
) -> Result<MountedCommand> {
    if argv.is_empty() {
        anyhow::bail!("command args are required unless --profile is used");
    }
    if !plan.is_workspace_app() {
        return Ok(MountedCommand {
            argv: argv.to_vec(),
            display: argv.join(" "),
            mounted: false,
        });
    }
    if command_is_workspace_qualified(argv) {
        return Ok(MountedCommand {
            argv: argv.to_vec(),
            display: argv.join(" "),
            mounted: false,
        });
    }

    let manager = argv[0].as_str();
    let mounted = match manager {
        "pnpm" => mount_filter_command("pnpm", argv, plan, false)?,
        "npm" => mount_npm_command(argv, plan)?,
        "yarn" => mount_yarn_command(argv, plan)?,
        "bun" => mount_filter_command("bun", argv, plan, true)?,
        _ => None,
    };

    let Some(argv) = mounted else {
        if !reject_unsupported_raw {
            return Ok(MountedCommand {
                argv: argv.to_vec(),
                display: argv.join(" "),
                mounted: false,
            });
        }
        anyhow::bail!(
            "raw app command cannot be safely mounted; use a profile or run with --app using a package-manager script"
        );
    };
    Ok(MountedCommand {
        display: argv.join(" "),
        argv,
        mounted: true,
    })
}

pub fn resolve_one_with_passphrase(
    selector: &TargetSelector,
    cwd: &Path,
    passphrase: &str,
) -> Result<WorkspaceTarget> {
    let mut target = resolve_one(selector, cwd)?;
    refresh_vault_with_passphrase(&mut target, passphrase);
    Ok(target)
}

pub fn resolve_many(selector: &TargetSelector, cwd: &Path) -> Result<Vec<WorkspaceTarget>> {
    if selector.project.is_some() && selector.app.is_some() {
        anyhow::bail!("choose either --project or --app, not both");
    }
    if !selector.all {
        return resolve_one(selector, cwd).map(|target| vec![target]);
    }
    if selector.project.is_some() || selector.app.is_some() {
        anyhow::bail!("--all cannot be combined with --project or --app");
    }
    let discovery = workspace::discover_containing(cwd)?
        .context("--all requires running inside a Ward workspace")?;
    let targets = configured_workspace_targets(&discovery)?;
    if targets.is_empty() {
        anyhow::bail!("workspace has no configured Ward app projects");
    }
    Ok(targets)
}

pub fn resolve_many_with_passphrase(
    selector: &TargetSelector,
    cwd: &Path,
    passphrase: &str,
) -> Result<Vec<WorkspaceTarget>> {
    let mut targets = resolve_many(selector, cwd)?;
    for target in &mut targets {
        refresh_vault_with_passphrase(target, passphrase);
    }
    Ok(targets)
}

pub fn configured_workspace_targets(
    discovery: &workspace::WorkspaceDiscovery,
) -> Result<Vec<WorkspaceTarget>> {
    let registry = registry::list_projects().unwrap_or_default();
    let mut targets = Vec::new();
    for package in discovery.app_candidates() {
        let Ok(cfg) = config::read_project_config(&package.path) else {
            continue;
        };
        let registered = registry.projects.get(&cfg.project);
        let vault = registered
            .map(|registered| registered.vault.clone())
            .unwrap_or_else(|| config::resolve_vault_path(&package.path, &cfg));
        targets.push(WorkspaceTarget {
            name: cfg.project,
            path: package.path.clone(),
            vault,
            workspace_root: Some(discovery.root.clone()),
            workspace_name: Some(discovery.workspace_name.clone()),
            app_slug: Some(package.slug.clone()),
            package_name: package.name.clone(),
        });
    }
    Ok(targets)
}

pub fn find_workspace_package_for_project<'a>(
    discovery: &'a workspace::WorkspaceDiscovery,
    project: &str,
) -> Option<&'a workspace::WorkspacePackage> {
    discovery.app_candidates().find(|package| {
        package.project_name == project
            || config::read_project_config(&package.path)
                .map(|cfg| cfg.project == project)
                .unwrap_or(false)
    })
}

pub fn register_workspace_metadata(
    project: &str,
    discovery: &workspace::WorkspaceDiscovery,
    package: &workspace::WorkspacePackage,
) -> Result<()> {
    registry::update_project_workspace_metadata(
        project,
        Some(discovery.root.clone()),
        Some(discovery.workspace_name.clone()),
        Some(package.slug.clone()),
        Some(discovery.workspace_name.clone()),
    )
}

pub fn target_suggestions(targets: &[WorkspaceTarget]) -> String {
    targets
        .iter()
        .map(|target| {
            let app = target.app_slug.as_deref().unwrap_or(&target.name);
            format!("{app} ({})", target.name)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn explicit_project(project: &str, cwd: &Path) -> Result<WorkspaceTarget> {
    let resolved = registry::resolve_project(Some(project), cwd)
        .context(format!("project {project} is not registered"))?;
    let mut target = target_from_resolved(resolved);
    attach_registry_metadata(&mut target);
    attach_workspace_metadata(&mut target)?;
    Ok(target)
}

fn explicit_app(app: &str, cwd: &Path) -> Result<WorkspaceTarget> {
    let discovery = workspace::discover_containing(cwd)?
        .context("--app requires running inside a Ward workspace")?;
    let package = discovery
        .app_candidates()
        .find(|package| package.matches(app))
        .with_context(|| format!("workspace app {app} was not found"))?;
    target_from_package(&discovery, package).with_context(|| {
        format!("workspace app {app} is not configured; run ward setup --workspace --app {app}")
    })
}

fn implicit_one(cwd: &Path) -> Result<WorkspaceTarget> {
    if let Some(project_root) = config::find_project_root(cwd) {
        let resolved = registry::resolve_project(None, &project_root)?;
        let mut target = target_from_resolved(resolved);
        attach_registry_metadata(&mut target);
        attach_workspace_metadata(&mut target)?;
        return Ok(target);
    }

    if let Some(discovery) = workspace::discover_containing(cwd)? {
        let targets = configured_workspace_targets(&discovery)?;
        return match targets.len() {
            0 => anyhow::bail!("workspace has no configured Ward app projects; run ward setup --workspace"),
            1 => Ok(targets.into_iter().next().expect("one target exists")),
            _ => anyhow::bail!(
                "workspace root has multiple Ward app projects; human mode is per app, so choose one with --app <app> or --project <project>, or run ward human inside each app folder: {}",
                target_suggestions(&targets)
            ),
        };
    }

    let resolved = registry::resolve_project(None, cwd)?;
    let mut target = target_from_resolved(resolved);
    attach_registry_metadata(&mut target);
    Ok(target)
}

fn target_from_package(
    discovery: &workspace::WorkspaceDiscovery,
    package: &workspace::WorkspacePackage,
) -> Result<WorkspaceTarget> {
    let cfg = config::read_project_config(&package.path)?;
    let registry = registry::list_projects().unwrap_or_default();
    let vault = registry
        .projects
        .get(&cfg.project)
        .map(|registered| registered.vault.clone())
        .unwrap_or_else(|| config::resolve_vault_path(&package.path, &cfg));
    Ok(WorkspaceTarget {
        name: cfg.project,
        path: package.path.clone(),
        vault,
        workspace_root: Some(discovery.root.clone()),
        workspace_name: Some(discovery.workspace_name.clone()),
        app_slug: Some(package.slug.clone()),
        package_name: package.name.clone(),
    })
}

fn target_from_resolved(resolved: registry::ResolvedProject) -> WorkspaceTarget {
    WorkspaceTarget {
        name: resolved.name,
        path: resolved.path,
        vault: resolved.vault,
        workspace_root: None,
        workspace_name: None,
        app_slug: None,
        package_name: None,
    }
}

fn attach_registry_metadata(target: &mut WorkspaceTarget) {
    let Ok(registry) = registry::list_projects() else {
        return;
    };
    let Some(registered) = registry.projects.get(&target.name) else {
        return;
    };
    target.workspace_root = registered.workspace_root.clone();
    target.workspace_name = registered.workspace_name.clone();
    target.app_slug = registered.app_slug.clone();
}

fn attach_workspace_metadata(target: &mut WorkspaceTarget) -> Result<()> {
    let discovery = if let Some(root) = target.workspace_root.as_deref() {
        workspace::discover(root)?
    } else {
        workspace::discover_containing(&target.path)?
    };
    let Some(discovery) = discovery else {
        return Ok(());
    };
    if let Some(package) = find_workspace_package_for_target(&discovery, target) {
        target.workspace_root = Some(discovery.root.clone());
        target.workspace_name = Some(discovery.workspace_name.clone());
        target.app_slug = Some(package.slug.clone());
        target.package_name = package.name.clone();
    }
    Ok(())
}

fn find_workspace_package_for_target<'a>(
    discovery: &'a workspace::WorkspaceDiscovery,
    target: &WorkspaceTarget,
) -> Option<&'a workspace::WorkspacePackage> {
    discovery.app_candidates().find(|package| {
        package.project_name == target.name
            || target
                .app_slug
                .as_deref()
                .is_some_and(|app| package.matches(app))
            || target
                .package_name
                .as_deref()
                .is_some_and(|name| package.matches(name))
            || same_path(&package.path, &target.path)
            || config::read_project_config(&package.path)
                .map(|cfg| cfg.project == target.name)
                .unwrap_or(false)
    })
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right || left.canonicalize().ok() == right.canonicalize().ok()
}

fn relative_path(root: &Path, path: &Path) -> Option<PathBuf> {
    path.strip_prefix(root)
        .ok()
        .map(Path::to_path_buf)
        .or_else(|| {
            let root = root.canonicalize().ok()?;
            let path = path.canonicalize().ok()?;
            path.strip_prefix(root).ok().map(Path::to_path_buf)
        })
}

fn workspace_selector(plan: &WorkspaceExecutionPlan, allow_slug: bool) -> Option<String> {
    plan.package_name
        .clone()
        .or_else(|| allow_slug.then(|| plan.app_slug.clone()).flatten())
}

fn app_relative_selector(plan: &WorkspaceExecutionPlan) -> Option<String> {
    plan.app_relative_path
        .as_ref()
        .map(|path| path.to_string_lossy().to_string())
}

fn command_is_workspace_qualified(argv: &[String]) -> bool {
    match argv.first().map(String::as_str) {
        Some("pnpm" | "bun") => has_workspace_flag(&argv[1..], &["--filter", "-F"]),
        Some("npm") => has_workspace_flag(&argv[1..], &["--workspace", "-w"]),
        Some("yarn") => argv.get(1).is_some_and(|arg| arg == "workspace"),
        _ => false,
    }
}

fn has_workspace_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|arg| {
        flags.iter().any(|flag| {
            arg == flag
                || arg
                    .strip_prefix(flag)
                    .is_some_and(|rest| rest.starts_with('='))
        })
    })
}

fn mount_filter_command(
    binary: &str,
    argv: &[String],
    plan: &WorkspaceExecutionPlan,
    force_run: bool,
) -> Result<Option<Vec<String>>> {
    if !is_package_script_command(argv, &plan.package_scripts) {
        return Ok(None);
    }
    let Some(selector) = workspace_selector(plan, true) else {
        anyhow::bail!("workspace app is missing package name or app slug");
    };
    let mut out = vec![binary.to_string(), "--filter".to_string(), selector];
    if force_run && argv.get(1).is_none_or(|arg| arg != "run") {
        out.push("run".to_string());
    }
    out.extend(argv[1..].iter().cloned());
    Ok(Some(out))
}

fn mount_npm_command(
    argv: &[String],
    plan: &WorkspaceExecutionPlan,
) -> Result<Option<Vec<String>>> {
    if !is_package_script_command(argv, &plan.package_scripts) {
        return Ok(None);
    }
    let Some(selector) = app_relative_selector(plan) else {
        anyhow::bail!("workspace app is missing a relative path");
    };
    let mut out = vec!["npm".to_string(), "--workspace".to_string(), selector];
    if argv.get(1).is_some_and(|arg| arg == "run") {
        out.extend(argv[1..].iter().cloned());
    } else {
        out.push("run".to_string());
        out.extend(argv[1..].iter().cloned());
    }
    Ok(Some(out))
}

fn mount_yarn_command(
    argv: &[String],
    plan: &WorkspaceExecutionPlan,
) -> Result<Option<Vec<String>>> {
    if !is_package_script_command(argv, &plan.package_scripts) {
        return Ok(None);
    }
    let Some(selector) = workspace_selector(plan, true) else {
        anyhow::bail!("workspace app is missing package name or app slug");
    };
    let mut out = vec!["yarn".to_string(), "workspace".to_string(), selector];
    out.extend(argv[1..].iter().cloned());
    Ok(Some(out))
}

fn is_package_script_command(argv: &[String], scripts: &[String]) -> bool {
    let Some(script) = script_name(argv) else {
        return false;
    };
    !script.starts_with('-') && scripts.iter().any(|known| known == script)
}

fn script_name(argv: &[String]) -> Option<&str> {
    match argv.get(1).map(String::as_str) {
        Some("run") => argv.get(2).map(String::as_str),
        Some(script) => Some(script),
        None => None,
    }
}

fn refresh_vault_with_passphrase(target: &mut WorkspaceTarget, passphrase: &str) {
    if let Ok(config) = config::read_project_config(&target.path) {
        if config.project == target.name {
            target.vault =
                config::resolve_vault_path_with_passphrase(&target.path, &config, passphrase);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> WorkspaceExecutionPlan {
        let target = WorkspaceTarget {
            name: "workspace:web".to_string(),
            path: PathBuf::from("/repo/apps/web"),
            vault: PathBuf::from("/repo/apps/web/.env.vault"),
            workspace_root: Some(PathBuf::from("/repo")),
            workspace_name: Some("workspace".to_string()),
            app_slug: Some("web".to_string()),
            package_name: Some("@workspace/web".to_string()),
        };
        WorkspaceExecutionPlan {
            workspace_root: Some(PathBuf::from("/repo")),
            app_path: PathBuf::from("/repo/apps/web"),
            app_relative_path: Some(PathBuf::from("apps/web")),
            app_slug: Some("web".to_string()),
            package_name: Some("@workspace/web".to_string()),
            package_scripts: vec!["dev".to_string(), "payload".to_string()],
            project: "workspace:web".to_string(),
            vault: PathBuf::from("/repo/apps/web/.env.vault"),
            execution_cwd: PathBuf::from("/repo"),
            workspace_package_manager: Some("pnpm".to_string()),
            target,
        }
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn mounts_supported_package_manager_script_commands() {
        let plan = plan();

        assert_eq!(
            mount_command(&plan, &args(&["pnpm", "dev"])).unwrap().argv,
            args(&["pnpm", "--filter", "@workspace/web", "dev"])
        );
        assert_eq!(
            mount_command(&plan, &args(&["npm", "run", "dev"]))
                .unwrap()
                .argv,
            args(&["npm", "--workspace", "apps/web", "run", "dev"])
        );
        assert_eq!(
            mount_command(&plan, &args(&["npm", "dev"])).unwrap().argv,
            args(&["npm", "--workspace", "apps/web", "run", "dev"])
        );
        assert_eq!(
            mount_command(&plan, &args(&["yarn", "dev"])).unwrap().argv,
            args(&["yarn", "workspace", "@workspace/web", "dev"])
        );
        assert_eq!(
            mount_command(&plan, &args(&["bun", "run", "dev"]))
                .unwrap()
                .argv,
            args(&["bun", "--filter", "@workspace/web", "run", "dev"])
        );
        assert_eq!(
            mount_command(&plan, &args(&["bun", "dev"])).unwrap().argv,
            args(&["bun", "--filter", "@workspace/web", "run", "dev"])
        );
        assert_eq!(
            mount_command(&plan, &args(&["pnpm", "payload", "migrate"]))
                .unwrap()
                .argv,
            args(&["pnpm", "--filter", "@workspace/web", "payload", "migrate"])
        );
    }

    #[test]
    fn leaves_already_workspace_qualified_commands_unchanged() {
        let plan = plan();
        for command in [
            args(&["pnpm", "--filter", "@workspace/web", "dev"]),
            args(&["pnpm", "-F", "@workspace/web", "dev"]),
            args(&["npm", "--workspace", "apps/web", "run", "dev"]),
            args(&["npm", "-w", "apps/web", "run", "dev"]),
            args(&["yarn", "workspace", "@workspace/web", "dev"]),
            args(&["bun", "--filter", "@workspace/web", "run", "dev"]),
        ] {
            let mounted = mount_command(&plan, &command).unwrap();
            assert_eq!(mounted.argv, command);
            assert!(!mounted.mounted);
        }
    }

    #[test]
    fn rejects_unsupported_raw_app_commands() {
        let plan = plan();

        let err = mount_command(&plan, &args(&["node", "server.js"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("raw app command cannot be safely mounted"));

        let install = mount_command(&plan, &args(&["pnpm", "install"]))
            .unwrap_err()
            .to_string();
        assert!(install.contains("raw app command cannot be safely mounted"));

        let profile_command = mount_profile_command(&plan, &args(&["node", "server.js"])).unwrap();
        assert_eq!(profile_command.argv, args(&["node", "server.js"]));
        assert!(!profile_command.mounted);
    }

    #[test]
    fn returns_plain_commands_for_non_workspace_projects() {
        let mut plan = plan();
        plan.workspace_root = None;
        plan.app_relative_path = None;

        let mounted = mount_command(&plan, &args(&["pnpm", "dev"])).unwrap();

        assert_eq!(mounted.argv, args(&["pnpm", "dev"]));
        assert!(!mounted.mounted);
    }
}
