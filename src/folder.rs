//! `_folder.toml`: per-folder variables, run order, and default data file.
//!
//! Settings apply to every request beneath the folder; for variables, nearer
//! folders override farther ones. Folder variables have the lowest precedence
//! (an environment overrides them), so they work as collection defaults.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::project::{ENVS_DIR, Project};

/// File name of a folder config.
pub const FOLDER_FILE: &str = "_folder.toml";

/// Parsed `_folder.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FolderConfig {
    /// Run order: file names (`login.curl`) or subfolders (`admin/`). Unlisted
    /// entries run afterwards: files first, then folders, each alphabetically.
    pub order: Vec<String>,
    /// Data file (CSV or JSON) used when this folder is run directly.
    pub data: Option<String>,
    /// Variable defaults for requests beneath this folder.
    pub vars: BTreeMap<String, toml::Value>,
    /// Auth for requests beneath this folder (nearest wins; `type = "none"` stops inheritance).
    pub auth: Option<crate::oauth::AuthConfig>,
}

/// A folder variable with where it was declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderVar {
    /// Variable name.
    pub name: String,
    /// Value as a string (non-string TOML values use their TOML text).
    pub value: String,
    /// Collection-relative `_folder.toml` path.
    pub location: String,
}

/// Converts a TOML scalar to the string curl will see.
fn toml_to_string(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Loads `<dir>/_folder.toml` if present.
pub fn load(dir: &Path) -> Result<Option<FolderConfig>> {
    let path = dir.join(FOLDER_FILE);
    if !path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)?;
    let cfg: FolderConfig =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(cfg))
}

/// Folder configs from the root down to the folder containing `rel_file`,
/// as `(collection-relative _folder.toml path, config)`.
pub fn chain(project: &Project, rel_file: &Path) -> Result<Vec<(PathBuf, FolderConfig)>> {
    let mut dirs = vec![PathBuf::new()];
    if let Some(parent) = rel_file.parent() {
        let mut acc = PathBuf::new();
        for c in parent.components() {
            acc.push(c);
            dirs.push(acc.clone());
        }
    }
    let mut out = Vec::new();
    for d in dirs {
        if let Some(cfg) = load(&project.root.join(&d))? {
            out.push((d.join(FOLDER_FILE), cfg));
        }
    }
    Ok(out)
}

/// Variables inherited by `rel_file`, farthest first (so later entries win).
pub fn folder_vars(project: &Project, rel_file: &Path) -> Result<Vec<FolderVar>> {
    let mut out = Vec::new();
    for (path, cfg) in chain(project, rel_file)? {
        for (name, value) in &cfg.vars {
            out.push(FolderVar {
                name: name.clone(),
                value: toml_to_string(value),
                location: path.display().to_string(),
            });
        }
    }
    Ok(out)
}

/// Expands a collection-relative folder into its request files in run order.
pub fn expand(project: &Project, rel_dir: &Path) -> Result<Vec<PathBuf>> {
    let abs = project.root.join(rel_dir);
    let cfg = load(&abs)?.unwrap_or_default();
    let mut files = BTreeSet::new();
    let mut dirs = BTreeSet::new();
    for entry in std::fs::read_dir(&abs).with_context(|| format!("reading {}", abs.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || name.starts_with('_') {
            continue;
        }
        let rel = rel_dir.join(&name);
        if entry.path().is_dir() {
            if rel != Path::new(ENVS_DIR) {
                dirs.insert(name);
            }
        } else if crate::curlconf::is_request_name(&name) {
            files.insert(name);
        }
    }
    let mut out = Vec::new();
    for item in &cfg.order {
        if let Some(d) = item.strip_suffix('/') {
            if !dirs.remove(d) {
                bail!(
                    "{}: order lists `{item}`, but there is no such folder",
                    rel_dir.join(FOLDER_FILE).display()
                );
            }
            out.extend(expand(project, &rel_dir.join(d))?);
        } else if files.remove(item) {
            out.push(rel_dir.join(item));
        } else {
            bail!(
                "{}: order lists `{item}`, but there is no such request file",
                rel_dir.join(FOLDER_FILE).display()
            );
        }
    }
    out.extend(files.into_iter().map(|f| rel_dir.join(f)));
    for d in dirs {
        out.extend(expand(project, &rel_dir.join(d))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn project() -> (tempfile::TempDir, Project) {
        let tmp = tempfile::tempdir().unwrap();
        crate::project::init(
            tmp.path(),
            &crate::project::InitOptions {
                name: Some("t"),
                ..Default::default()
            },
        )
        .unwrap();
        fs::remove_file(tmp.path().join("example.curl")).unwrap();
        for f in [
            "a.curl",
            "b.curl",
            "sub/x.curl",
            "sub/y.curl",
            "other/z.curl",
            "envs/local.curl",
        ] {
            let p = tmp.path().join(f);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, "url = x\n").unwrap();
        }
        fs::write(
            tmp.path().join(FOLDER_FILE),
            "order = [\"sub/\", \"b.curl\"]\n[vars]\nshared = \"root\"\nroot_only = 1\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("sub").join(FOLDER_FILE),
            "order = [\"y.curl\"]\n[vars]\nshared = \"sub\"\n",
        )
        .unwrap();
        let p = Project::load(tmp.path()).unwrap();
        (tmp, p)
    }

    #[test]
    fn expands_in_declared_then_alphabetical_order() {
        let (_t, p) = project();
        let order: Vec<String> = expand(&p, Path::new(""))
            .unwrap()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(
            order,
            vec![
                "sub/y.curl",
                "sub/x.curl",
                "b.curl",
                "a.curl",
                "other/z.curl"
            ]
        );
    }

    #[test]
    fn nearer_folder_vars_come_last() {
        let (_t, p) = project();
        let vars = folder_vars(&p, Path::new("sub/x.curl")).unwrap();
        let pairs: Vec<_> = vars
            .iter()
            .map(|v| (v.name.as_str(), v.value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![("root_only", "1"), ("shared", "root"), ("shared", "sub")]
        );
        assert_eq!(vars[2].location, "sub/_folder.toml");
        assert_eq!(folder_vars(&p, Path::new("a.curl")).unwrap().len(), 2);
    }

    #[test]
    fn bad_order_entries_fail() {
        let (t, p) = project();
        fs::write(
            t.path().join("other").join(FOLDER_FILE),
            "order = [\"missing.curl\"]\n",
        )
        .unwrap();
        assert!(
            expand(&p, Path::new("other"))
                .unwrap_err()
                .to_string()
                .contains("missing.curl")
        );
        fs::write(t.path().join("other").join(FOLDER_FILE), "ordr = []\n").unwrap();
        assert!(expand(&p, Path::new("other")).is_err());
    }
}
