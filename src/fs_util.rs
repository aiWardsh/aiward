use std::{
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};

pub(crate) fn resolve_inside_base(base: &Path, candidate: &Path, label: &str) -> Result<PathBuf> {
    if has_parent_component(candidate) {
        anyhow::bail!("{label} must not contain parent directory traversal");
    }

    let base_abs = absolutize(base)?;
    let base_norm = normalize_lexical(&base_abs);
    let candidate_abs = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base_norm.join(candidate)
    };
    let candidate_norm = normalize_lexical(&candidate_abs);

    let base_real = base_norm
        .canonicalize()
        .unwrap_or_else(|_| base_norm.clone());
    let check_path = nearest_existing_path(&candidate_norm);
    let real_path = check_path.canonicalize().ok();
    if !candidate_norm.starts_with(&base_norm)
        && !real_path
            .as_ref()
            .is_some_and(|path| path.starts_with(&base_real))
    {
        anyhow::bail!(
            "{label} must stay inside {}; got {}",
            base_real.display(),
            candidate.display()
        );
    }
    if let Some(real_path) = real_path {
        if !real_path.starts_with(&base_real) {
            anyhow::bail!(
                "{label} must stay inside {}; got {}",
                base_real.display(),
                candidate.display()
            );
        }
    }

    Ok(candidate_norm)
}

pub(crate) fn resolve_project_path(
    project_root: &Path,
    candidate: &Path,
    label: &str,
) -> Result<PathBuf> {
    resolve_inside_base(project_root, candidate, label)
}

pub(crate) fn resolve_ward_home_path(candidate: &Path, label: &str) -> Result<PathBuf> {
    resolve_inside_base(&ward_home_base(), candidate, label)
}

pub(crate) fn resolve_existing_external_file(path: &Path, label: &str) -> Result<PathBuf> {
    let resolved = path
        .canonicalize()
        .with_context(|| format!("{label} not found: {}", path.display()))?;
    if !resolved.is_file() {
        anyhow::bail!("{label} is not a file: {}", resolved.display());
    }
    Ok(resolved)
}

pub(crate) fn checked_existing_file(path: &Path, label: &str) -> Result<PathBuf> {
    reject_parent_traversal(path, label)?;
    resolve_existing_external_file(path, label)
}

pub(crate) fn read_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let resolved = checked_existing_file(path, label)?;
    fs::read(&resolved).context(format!("failed to read {}", resolved.display()))
}

pub(crate) fn read_file_to_string(path: &Path, label: &str) -> Result<String> {
    let resolved = checked_existing_file(path, label)?;
    fs::read_to_string(&resolved).context(format!("failed to read {}", resolved.display()))
}

pub(crate) fn resolve_existing_external_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let resolved = path
        .canonicalize()
        .with_context(|| format!("{label} not found: {}", path.display()))?;
    if !resolved.is_dir() {
        anyhow::bail!("{label} is not a directory: {}", resolved.display());
    }
    Ok(resolved)
}

pub(crate) fn reject_parent_traversal(path: &Path, label: &str) -> Result<()> {
    if has_parent_component(path) {
        anyhow::bail!("{label} must not contain parent directory traversal");
    }
    Ok(())
}

pub(crate) fn resolve_external_output(path: &Path, label: &str) -> Result<PathBuf> {
    reject_parent_traversal(path, label)?;
    let resolved = absolutize(path)?;
    if let Some(parent) = resolved.parent() {
        let parent_real = parent
            .canonicalize()
            .with_context(|| format!("failed to resolve parent for {}", path.display()))?;
        Ok(parent_real.join(
            resolved
                .file_name()
                .context("output path must include a file name")?,
        ))
    } else {
        Ok(resolved)
    }
}

pub(crate) fn resolve_external_directory_output(path: &Path, label: &str) -> Result<PathBuf> {
    reject_parent_traversal(path, label)?;
    let resolved = absolutize(path)?;
    let existing = nearest_existing_path(&resolved);
    if let Ok(existing_real) = existing.canonicalize() {
        if let Ok(suffix) = resolved.strip_prefix(&existing) {
            return Ok(existing_real.join(suffix));
        }
    }
    Ok(resolved)
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("failed to resolve current directory")?
            .join(path))
    }
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn nearest_existing_path(path: &Path) -> PathBuf {
    let mut current = path;
    loop {
        if current.exists() {
            return current.to_path_buf();
        }
        let Some(parent) = current.parent() else {
            return path.to_path_buf();
        };
        current = parent;
    }
}

fn ward_home_base() -> PathBuf {
    match std::env::var("WARD_HOME")
        .ok()
        .filter(|path| !path.trim().is_empty())
    {
        Some(path) => PathBuf::from(path),
        None => dirs::home_dir().unwrap_or(PathBuf::from(".")).join(".ward"),
    }
}

pub(crate) fn ensure_parent_dir(path: &Path) -> Result<()> {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => {
            fs::create_dir_all(parent).context(format!("failed to create {}", parent.display()))
        }
        None => Ok(()),
    }
}

pub(crate) fn ensure_private_parent_dir(path: &Path) -> Result<()> {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => ensure_private_dir(parent),
        None => Ok(()),
    }
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context(format!("failed to create {}", path.display()))?;
    set_private_dir_permissions(path)
}

pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    ensure_private_parent_dir(path)?;
    fs::write(path, contents).context(format!("failed to write {}", path.display()))?;
    set_private_file_permissions(path)
}

pub(crate) fn open_private_append(path: &Path) -> Result<File> {
    ensure_private_parent_dir(path)?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context(format!("failed to open {}", path.display()))?;
    set_private_file_permissions(path)?;
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .context(format!("failed to chmod {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context(format!("failed to chmod {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn ensure_parent_dir_creates_parent_and_allows_plain_file_name() {
        let tempdir = tempfile::tempdir().unwrap();
        let nested = tempdir.path().join("nested").join("file.txt");

        ensure_parent_dir(&nested).unwrap();
        ensure_parent_dir(Path::new("file.txt")).unwrap();
        ensure_private_parent_dir(Path::new("file.txt")).unwrap();

        assert!(tempdir.path().join("nested").is_dir());
    }

    #[test]
    fn private_file_helpers_write_and_append() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("state").join("file.jsonl");

        write_private_file(&path, b"one\n").unwrap();
        {
            use std::io::Write;
            let mut file = open_private_append(&path).unwrap();
            writeln!(file, "two").unwrap();
        }

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\n");

        #[cfg(unix)]
        {
            let dir_mode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    #[test]
    fn private_helpers_report_blocked_paths() {
        let tempdir = tempfile::tempdir().unwrap();
        let blocked = tempdir.path().join("blocked");
        std::fs::write(&blocked, "").unwrap();

        assert!(ensure_private_dir(&blocked).is_err());
        assert!(write_private_file(&blocked, b"contents").is_ok());
        assert!(open_private_append(&blocked).is_ok());
    }

    #[test]
    fn resolve_inside_base_rejects_parent_traversal_and_absolute_escape() {
        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        let parent_error =
            resolve_inside_base(base.path(), Path::new("../outside.vault"), "vault path")
                .unwrap_err()
                .to_string();
        assert!(parent_error.contains("parent directory traversal"));

        let absolute_error = resolve_inside_base(
            base.path(),
            &outside.path().join("outside.vault"),
            "vault path",
        )
        .unwrap_err()
        .to_string();
        assert!(absolute_error.contains("must stay inside"));
    }

    #[test]
    fn resolve_inside_base_accepts_relative_and_absolute_inside_base() {
        let base = tempfile::tempdir().unwrap();
        let nested = base.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let relative =
            resolve_inside_base(base.path(), Path::new("nested/.env.vault"), "vault").unwrap();
        let absolute =
            resolve_inside_base(base.path(), &nested.join(".env.vault"), "vault").unwrap();

        assert_eq!(relative, nested.join(".env.vault"));
        assert_eq!(absolute, nested.join(".env.vault"));
    }

    #[test]
    #[cfg(unix)]
    fn resolve_inside_base_rejects_symlink_escape() {
        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        let error = resolve_inside_base(base.path(), Path::new("link/secret.env"), "vault path")
            .unwrap_err()
            .to_string();

        assert!(error.contains("must stay inside"));
    }

    #[test]
    fn checked_read_helpers_reject_parent_traversal() {
        let error = read_file(Path::new("../outside.env"), "dotenv file")
            .unwrap_err()
            .to_string();

        assert!(error.contains("parent directory traversal"));
    }

    #[test]
    fn checked_read_helpers_read_existing_files() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("state.json");
        std::fs::write(&path, "{\"ok\":true}\n").unwrap();

        assert_eq!(
            read_file_to_string(&path, "state file").unwrap(),
            "{\"ok\":true}\n"
        );
        assert_eq!(read_file(&path, "state file").unwrap(), b"{\"ok\":true}\n");
    }
}
