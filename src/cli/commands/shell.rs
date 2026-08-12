fn prompt_shell_reload(_rc: &Path) {
    #[cfg(not(coverage))]
    {
        let reload = inquire::Confirm::new("Reload your shell now to activate Ward hooks?")
            .with_help_message("After reload, run ward human to protect this terminal.")
            .with_default(true)
            .prompt()
            .unwrap_or(false);
        if reload {
            let marker = broker::run_dir().join("shell-reload");
            crate::fs_util::ensure_private_dir(&broker::run_dir()).ok();
            fs::write(&marker, "").ok();
            // Fallback if the ward() shell function isn't installed yet.
            term::next("reload with: exec $SHELL && ward human");
        } else {
            term::next("when ready: exec $SHELL && ward human");
        }
    }
    #[cfg(coverage)]
    {
        let _ = rc;
        term::next("reload with: exec $SHELL && ward human");
    }
}

fn ensure_shell_integration() -> Option<PathBuf> {
    let shell = detect_shell()?;
    let rc_path = shell_rc_path(&shell)?;
    let contents = fs::read_to_string(&rc_path).unwrap_or_default();
    let updated = install_shell_integration_contents(&shell, &contents);
    if updated == contents {
        return None;
    }
    if fs::write(&rc_path, updated).is_ok() {
        Some(rc_path)
    } else {
        None
    }
}

fn install_shell_integration_contents(shell: &str, contents: &str) -> String {
    let mut updated = strip_ward_shell_integration(contents)
        .trim_end_matches('\n')
        .to_string();
    if !updated.is_empty() {
        updated.push_str("\n\n");
    }
    if !shell_path_present(&updated, shell) {
        updated.push_str(shell_path_snippet(shell));
        updated.push('\n');
    }
    updated.push_str(shell_integration_snippet(shell));
    updated
}

fn strip_ward_shell_integration(contents: &str) -> String {
    let lines = contents.lines().collect::<Vec<_>>();
    let mut retained = Vec::with_capacity(lines.len());
    let mut index = 0;
    while index < lines.len() {
        if lines[index].trim() == "# ward shell integration" {
            index += 1;
            if index < lines.len() {
                let next = lines[index].trim();
                if next == "if command -v ward >/dev/null 2>&1; then" || next == "if type -q ward" {
                    index += 1;
                    while index < lines.len()
                        && lines[index].trim() != "fi"
                        && lines[index].trim() != "end"
                    {
                        index += 1;
                    }
                    if index < lines.len() {
                        index += 1;
                    }
                } else if next == "eval \"$(ward shell-init)\""
                    || next == "ward shell-init | source"
                {
                    index += 1;
                }
            }
            while index < lines.len() && lines[index].trim().is_empty() {
                index += 1;
            }
            continue;
        }
        retained.push(lines[index]);
        index += 1;
    }
    let mut stripped = retained.join("\n");
    if contents.ends_with('\n') && !stripped.is_empty() {
        stripped.push('\n');
    }
    stripped
}

fn shell_path_present(contents: &str, shell: &str) -> bool {
    if shell == "fish" {
        contents.contains(".cargo/bin")
    } else {
        contents.contains("export PATH=\"$HOME/.cargo/bin:$PATH\"")
            || contents.contains("export PATH=\"$HOME/.cargo/bin:${PATH}\"")
            || contents.contains("export PATH=$HOME/.cargo/bin:$PATH")
    }
}

fn shell_path_snippet(shell: &str) -> &'static str {
    if shell == "fish" {
        "# Added by ward installer\nfish_add_path \"$HOME/.cargo/bin\"\n"
    } else {
        "# Added by ward installer\nexport PATH=\"$HOME/.cargo/bin:$PATH\"\n"
    }
}

fn shell_integration_snippet(shell: &str) -> &'static str {
    if shell == "fish" {
        "# ward shell integration\nif type -q ward\n    set -gx WARD_SHELL_INTEGRATION 1\n    ward shell-init | source\nend\n"
    } else {
        "# ward shell integration\nif command -v ward >/dev/null 2>&1; then\n  export WARD_SHELL_INTEGRATION=1\n  eval \"$(ward shell-init)\"\nfi\n"
    }
}

fn shell_rc_path(shell: &str) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let path = match shell {
        "zsh" => home.join(".zshrc"),
        "bash" => {
            let candidate = home.join(".bashrc");
            if candidate.exists() {
                candidate
            } else {
                home.join(".bash_profile")
            }
        }
        "fish" => home.join(".config").join("fish").join("config.fish"),
        _ => return None,
    };
    Some(path)
}

fn shell_init(shell_override: Option<&str>) -> Result<()> {
    let shell = shell_override
        .map(str::to_string)
        .or_else(detect_shell)
        .unwrap_or_else(|| "sh".to_string());
    print!("{}", shell_init_code(&shell));
    Ok(())
}

fn detect_shell() -> Option<String> {
    std::env::var("SHELL").ok().and_then(|s| {
        std::path::Path::new(&s)
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
    })
}

fn collect_command_prefixes(cwd: &Path) -> Vec<String> {
    let mut prefixes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for prefix in default_human_wrapped_commands() {
        prefixes.insert(prefix.to_string());
    }

    if let Ok(project_config) = config::read_project_config(cwd) {
        for profile in project_config.profiles.values() {
            if let Some(prefix) = profile.command.split_whitespace().next() {
                prefixes.insert(prefix.to_string());
            }
        }
        for preset in &project_config.presets {
            for cmd in &preset.match_commands {
                if let Some(prefix) = cmd.split_whitespace().next() {
                    prefixes.insert(prefix.to_string());
                }
            }
        }
    }

    if let Ok(mode_configs) = modes::load_local_modes(cwd) {
        for mode in &mode_configs {
            for cmd in &mode.allowed_commands {
                if let Some(raw) = cmd.split_whitespace().next() {
                    let prefix = raw.trim_matches('*').trim_matches('/');
                    if !prefix.is_empty() {
                        prefixes.insert(prefix.to_string());
                    }
                }
            }
        }
    }

    prefixes
        .into_iter()
        .filter(|p| is_safe_shell_function_name(p))
        .collect()
}

fn default_human_wrapped_commands() -> &'static [&'static str] {
    &[
        "bun",
        "cargo",
        "deno",
        "dotenv",
        "drizzle-kit",
        "next",
        "node",
        "npm",
        "npx",
        "pnpm",
        "prisma",
        "tsx",
        "ts-node",
        "vite",
        "yarn",
    ]
}

fn is_safe_shell_function_name(name: &str) -> bool {
    if name == "ward" {
        return false;
    }
    const BUILTINS: &[&str] = &[
        "cd", "echo", "export", "source", ".", "exec", "exit", "set", "unset", "alias", "eval",
        "read", "printf", "test", "[", "[[", "true", "false", "return", "break", "continue",
        "shift", "trap",
    ];
    if BUILTINS.contains(&name) {
        return false;
    }
    name.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        && !name.starts_with('-')
}

fn shell_init_code(shell: &str) -> String {
    let ward_home = audit_logs::ward_home();
    let disabled_path = ward_home.join("disabled.json").display().to_string();
    let sock_path = ward_home
        .join("run")
        .join("human-$$/guardian.sock")
        .display()
        .to_string();

    let cwd = env::current_dir().unwrap_or_default();
    let cmds = collect_command_prefixes(&cwd);
    let cmds_ref: Vec<&str> = cmds.iter().map(String::as_str).collect();

    if shell == "fish" {
        fish_init_code(&ward_home, &disabled_path, &cmds_ref)
    } else {
        posix_init_code(shell, &ward_home, &disabled_path, &sock_path, &cmds_ref)
    }
}

fn posix_init_code(
    shell: &str,
    ward_home: &std::path::Path,
    disabled_path: &str,
    sock_path: &str,
    cmds: &[&str],
) -> String {
    let mut out =
        String::from("# ward shell integration — only active in human mode inside ward projects\n");
    out.push_str("export WARD_SHELL_INTEGRATION=1\n");
    out.push_str("__ward_disabled() {\n");
    out.push_str(&format!("  [ -f \"{disabled_path}\" ]\n"));
    out.push_str("}\n");
    out.push_str("__ward_project_root() {\n");
    out.push_str("  __ward_dir=\"$PWD\"\n");
    out.push_str("  while [ -n \"$__ward_dir\" ]; do\n");
    out.push_str("    if [ -f \"$__ward_dir/.ward.json\" ]; then\n");
    out.push_str("      printf '%s\\n' \"$__ward_dir\"\n");
    out.push_str("      return 0\n");
    out.push_str("    fi\n");
    out.push_str("    if [ \"$__ward_dir\" = \"/\" ]; then\n");
    out.push_str("      break\n");
    out.push_str("    fi\n");
    out.push_str("    __ward_dir=$(dirname \"$__ward_dir\")\n");
    out.push_str("  done\n");
    out.push_str("  return 1\n");
    out.push_str("}\n");
    out.push_str("__ward_workspace_root() {\n");
    out.push_str("  __ward_dir=\"$PWD\"\n");
    out.push_str("  while [ -n \"$__ward_dir\" ]; do\n");
    out.push_str("    if [ -f \"$__ward_dir/pnpm-workspace.yaml\" ] || [ -f \"$__ward_dir/turbo.json\" ]; then\n");
    out.push_str("      printf '%s\\n' \"$__ward_dir\"\n");
    out.push_str("      return 0\n");
    out.push_str("    fi\n");
    out.push_str("    if [ \"$__ward_dir\" = \"/\" ]; then\n");
    out.push_str("      break\n");
    out.push_str("    fi\n");
    out.push_str("    __ward_dir=$(dirname \"$__ward_dir\")\n");
    out.push_str("  done\n");
    out.push_str("  return 1\n");
    out.push_str("}\n");
    out.push_str("__ward_app_from_command() {\n");
    out.push_str("  case \"$1\" in\n");
    out.push_str("    pnpm|npm|yarn|bun)\n");
    out.push_str("      __ward_manager=\"$1\"\n");
    out.push_str("      shift\n");
    out.push_str("      if [ \"$__ward_manager\" = \"yarn\" ] && [ \"$1\" = \"workspace\" ] && [ -n \"$2\" ]; then\n");
    out.push_str("        printf '%s\\n' \"$2\"\n");
    out.push_str("        return 0\n");
    out.push_str("      fi\n");
    out.push_str("      while [ $# -gt 0 ]; do\n");
    out.push_str("        case \"$1\" in\n");
    out.push_str("          --filter|--workspace|-F|-w)\n");
    out.push_str("            shift\n");
    out.push_str("            [ -n \"$1\" ] && printf '%s\\n' \"$1\" && return 0\n");
    out.push_str("            ;;\n");
    out.push_str("          --filter=*|--workspace=*|-F=*|-w=*)\n");
    out.push_str("            printf '%s\\n' \"${1#*=}\"\n");
    out.push_str("            return 0\n");
    out.push_str("            ;;\n");
    out.push_str("        esac\n");
    out.push_str("        shift\n");
    out.push_str("      done\n");
    out.push_str("      ;;\n");
    out.push_str("  esac\n");
    out.push_str("  return 1\n");
    out.push_str("}\n");
    out.push_str("__ward_wrap() {\n");
    out.push_str("  if __ward_disabled; then\n");
    out.push_str("    command \"$@\"\n");
    out.push_str("    return $?\n");
    out.push_str("  fi\n");
    out.push_str("  __ward_root=\"$(__ward_project_root)\"\n");
    out.push_str("  __ward_workspace=\"$(__ward_workspace_root)\"\n");
    out.push_str("  if [ -z \"$__ward_root\" ] && [ -z \"$__ward_workspace\" ]; then\n");
    out.push_str("    command \"$@\"\n");
    out.push_str("    return $?\n");
    out.push_str("  fi\n");
    out.push_str(&format!("  if [ -S \"{sock_path}\" ]; then\n"));
    out.push_str("    if [ -n \"$__ward_root\" ]; then\n");
    out.push_str("    WARD_HUMAN_SHELL_PID=$$ command ward run -- \"$@\"\n");
    out.push_str("    return $?\n");
    out.push_str("    fi\n");
    out.push_str("    __ward_app=\"$(__ward_app_from_command \"$@\")\"\n");
    out.push_str("    if [ -n \"$__ward_app\" ]; then\n");
    out.push_str(
        "      WARD_HUMAN_SHELL_PID=$$ command ward run --app \"$__ward_app\" -- \"$@\"\n",
    );
    out.push_str("      return $?\n");
    out.push_str("    fi\n");
    out.push_str("    printf '%s\\n' 'Ward could not map this workspace-root command to one app; rerun with ward run --app <app> -- <command>' >&2\n");
    out.push_str("    return 126\n");
    out.push_str("  fi\n");
    out.push_str(
        "  printf '%s\\n' 'Ward human mode is not active for this terminal; run ward human' >&2\n",
    );
    out.push_str("  printf '%s\\n' \"shell pid: $$\" >&2\n");
    out.push_str(&format!(
        "  printf '%s\\n' \"expected guardian: {sock_path}\" >&2\n"
    ));
    out.push_str("  return 126\n");
    out.push_str("}\n");
    if shell == "zsh" {
        out.push_str(&zsh_prompt_badge_code(disabled_path, sock_path));
    }
    let reload_marker = ward_home
        .join("run")
        .join("shell-reload")
        .display()
        .to_string();
    out.push_str("ward() {\n");
    out.push_str("  WARD_HUMAN_SHELL_PID=$$ command ward \"$@\"\n");
    out.push_str("  __ward_exit=$?\n");
    out.push_str("  case \"$1\" in\n");
    out.push_str("    setup|init)\n");
    out.push_str(&format!("      if [ -f \"{reload_marker}\" ]; then\n"));
    out.push_str(&format!("        rm -f \"{reload_marker}\"\n"));
    out.push_str("        exec $SHELL\n");
    out.push_str("      fi\n");
    out.push_str("      ;;\n");
    out.push_str("  esac\n");
    out.push_str("  return $__ward_exit\n");
    out.push_str("}\n");
    for cmd in cmds {
        out.push_str(&format!("{cmd}() {{ __ward_wrap {cmd} \"$@\"; }}\n"));
    }
    // Catch-all fallback: routes unknown commands through ward when in human mode.
    // bash uses command_not_found_handle, zsh uses command_not_found_handler.
    out.push_str("command_not_found_handle() { __ward_wrap \"$@\"; }\n");
    out.push_str("command_not_found_handler() { __ward_wrap \"$@\"; }\n");
    out
}

fn zsh_prompt_badge_code(disabled_path: &str, sock_path: &str) -> String {
    let mut out = String::new();
    out.push_str("if [ -n \"${ZSH_VERSION:-}\" ]; then\n");
    out.push_str("__WARD_HUMAN_BADGE='%F{135}◬ ward:human%f'\n");
    out.push_str("__WARD_LOCKED_BADGE='%F{244}ward:locked%f'\n");
    out.push_str("__ward_prompt_badge() {\n");
    out.push_str(&format!("  if [ -f \"{disabled_path}\" ]; then\n"));
    out.push_str("    return 0\n");
    out.push_str("  fi\n");
    out.push_str("  __ward_root=\"$(__ward_project_root)\"\n");
    out.push_str("  __ward_workspace=\"$(__ward_workspace_root)\"\n");
    out.push_str("  if [ -z \"$__ward_root\" ] && [ -z \"$__ward_workspace\" ]; then\n");
    out.push_str("    return 0\n");
    out.push_str("  fi\n");
    out.push_str(&format!("  if [ -S \"{sock_path}\" ]; then\n"));
    out.push_str("    printf '%s' \"$__WARD_HUMAN_BADGE\"\n");
    out.push_str("  else\n");
    out.push_str("    printf '%s' \"$__WARD_LOCKED_BADGE\"\n");
    out.push_str("  fi\n");
    out.push_str("}\n");
    out.push_str("__ward_prompt_without_badge() {\n");
    out.push_str("  __ward_prompt=\"${1:-}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// $__WARD_HUMAN_BADGE/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//$__WARD_HUMAN_BADGE/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// $__WARD_LOCKED_BADGE/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//$__WARD_LOCKED_BADGE/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// ◬ ward:human/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//◬ ward:human/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// ward:human/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//ward:human/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt// ward:locked/}\"\n");
    out.push_str("  __ward_prompt=\"${__ward_prompt//ward:locked/}\"\n");
    out.push_str("  printf '%s' \"$__ward_prompt\"\n");
    out.push_str("}\n");
    out.push_str("__ward_precmd() {\n");
    out.push_str("  __ward_badge=\"$(__ward_prompt_badge)\"\n");
    out.push_str("  RPROMPT=\"$(__ward_prompt_without_badge \"${RPROMPT:-}\")\"\n");
    out.push_str("  if [ -n \"$__ward_badge\" ]; then\n");
    out.push_str("    if [ -n \"$RPROMPT\" ]; then\n");
    out.push_str("      RPROMPT=\"$RPROMPT $__ward_badge\"\n");
    out.push_str("    else\n");
    out.push_str("      RPROMPT=\"$__ward_badge\"\n");
    out.push_str("    fi\n");
    out.push_str("  fi\n");
    out.push_str("}\n");
    out.push_str("if ! (( ${precmd_functions[(I)__ward_precmd]} )); then\n");
    out.push_str("  precmd_functions+=(__ward_precmd)\n");
    out.push_str("fi\n");
    out.push_str("__ward_precmd\n");
    out.push_str("fi\n");
    out
}

fn fish_init_code(ward_home: &std::path::Path, disabled_path: &str, cmds: &[&str]) -> String {
    let sock_dir = ward_home.join("run").display().to_string();
    let mut out =
        String::from("# ward shell integration — only active in human mode inside ward projects\n");
    out.push_str("set -gx WARD_SHELL_INTEGRATION 1\n");
    out.push_str("function __ward_disabled\n");
    out.push_str(&format!("    test -f \"{disabled_path}\"\n"));
    out.push_str("end\n");
    out.push_str("function __ward_project_root\n");
    out.push_str("    set dir (pwd)\n");
    out.push_str("    while test -n \"$dir\"\n");
    out.push_str("        if test -f \"$dir/.ward.json\"\n");
    out.push_str("            echo $dir\n");
    out.push_str("            return 0\n");
    out.push_str("        end\n");
    out.push_str("        if test \"$dir\" = \"/\"\n");
    out.push_str("            break\n");
    out.push_str("        end\n");
    out.push_str("        set dir (dirname \"$dir\")\n");
    out.push_str("    end\n");
    out.push_str("    return 1\n");
    out.push_str("end\n");
    out.push_str("function __ward_workspace_root\n");
    out.push_str("    set dir (pwd)\n");
    out.push_str("    while test -n \"$dir\"\n");
    out.push_str(
        "        if test -f \"$dir/pnpm-workspace.yaml\"; or test -f \"$dir/turbo.json\"\n",
    );
    out.push_str("            echo $dir\n");
    out.push_str("            return 0\n");
    out.push_str("        end\n");
    out.push_str("        if test \"$dir\" = \"/\"\n");
    out.push_str("            break\n");
    out.push_str("        end\n");
    out.push_str("        set dir (dirname \"$dir\")\n");
    out.push_str("    end\n");
    out.push_str("    return 1\n");
    out.push_str("end\n");
    out.push_str("function __ward_app_from_command\n");
    out.push_str("    switch $argv[1]\n");
    out.push_str("        case pnpm npm yarn bun\n");
    out.push_str("            set manager $argv[1]\n");
    out.push_str("            set args $argv[2..-1]\n");
    out.push_str("            if test \"$manager\" = \"yarn\"; and test \"$args[1]\" = \"workspace\"; and test -n \"$args[2]\"\n");
    out.push_str("                echo $args[2]\n");
    out.push_str("                return 0\n");
    out.push_str("            end\n");
    out.push_str("            set i 1\n");
    out.push_str("            while test $i -le (count $args)\n");
    out.push_str("                set arg $args[$i]\n");
    out.push_str(
        "                if test \"$arg\" = \"--filter\"; or test \"$arg\" = \"--workspace\"; or test \"$arg\" = \"-F\"; or test \"$arg\" = \"-w\"\n",
    );
    out.push_str("                    set i (math $i + 1)\n");
    out.push_str(
        "                    test $i -le (count $args); and echo $args[$i]; and return 0\n",
    );
    out.push_str("                else if string match -q -- '--filter=*' $arg; or string match -q -- '--workspace=*' $arg; or string match -q -- '-F=*' $arg; or string match -q -- '-w=*' $arg\n");
    out.push_str("                    string replace -r '^[^=]+=' '' $arg\n");
    out.push_str("                    return 0\n");
    out.push_str("                end\n");
    out.push_str("                set i (math $i + 1)\n");
    out.push_str("            end\n");
    out.push_str("    end\n");
    out.push_str("    return 1\n");
    out.push_str("end\n");
    out.push_str("function __ward_wrap\n");
    // Use $fish_pid directly — it's the fish shell PID, matching getppid() in child processes.
    out.push_str(&format!(
        "    set sock \"{sock_dir}/human-$fish_pid/guardian.sock\"\n"
    ));
    out.push_str("    if __ward_disabled\n");
    out.push_str("        command $argv\n");
    out.push_str("        return $status\n");
    out.push_str("    end\n");
    out.push_str("    set project_root (__ward_project_root)\n");
    out.push_str("    set workspace_root (__ward_workspace_root)\n");
    out.push_str("    if test -z \"$project_root\"; and test -z \"$workspace_root\"\n");
    out.push_str("        command $argv\n");
    out.push_str("        return $status\n");
    out.push_str("    end\n");
    out.push_str("    if test -S $sock\n");
    out.push_str("        if test -n \"$project_root\"\n");
    out.push_str("        env WARD_HUMAN_SHELL_PID=$fish_pid command ward run -- $argv\n");
    out.push_str("        return $status\n");
    out.push_str("        end\n");
    out.push_str("        set app (__ward_app_from_command $argv)\n");
    out.push_str("        if test -n \"$app\"\n");
    out.push_str(
        "            env WARD_HUMAN_SHELL_PID=$fish_pid command ward run --app \"$app\" -- $argv\n",
    );
    out.push_str("            return $status\n");
    out.push_str("        end\n");
    out.push_str("        echo 'Ward could not map this workspace-root command to one app; rerun with ward run --app <app> -- <command>' >&2\n");
    out.push_str("        return 126\n");
    out.push_str("    else\n");
    out.push_str(
        "        echo 'Ward human mode is not active for this terminal; run ward human' >&2\n",
    );
    out.push_str("        echo \"shell pid: $fish_pid\" >&2\n");
    out.push_str("        echo \"expected guardian: $sock\" >&2\n");
    out.push_str("        return 126\n");
    out.push_str("    end\n");
    out.push_str("end\n");
    out.push_str("function ward\n");
    out.push_str("    env WARD_HUMAN_SHELL_PID=$fish_pid command ward $argv\n");
    out.push_str("    set __ward_exit $status\n");
    out.push_str("    if contains -- $argv[1] setup init\n");
    out.push_str("        source ~/.config/fish/config.fish 2>/dev/null\n");
    out.push_str("    end\n");
    out.push_str("    return $__ward_exit\n");
    out.push_str("end\n");
    for cmd in cmds {
        out.push_str(&format!("function {cmd}; __ward_wrap {cmd} $argv; end\n"));
    }
    // Catch-all fallback for any command not found in PATH while in human mode.
    out.push_str("function __ward_command_not_found --on-event fish_command_not_found\n");
    out.push_str("    __ward_wrap $argv\n");
    out.push_str("end\n");
    out
}
