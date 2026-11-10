//! Collection root discovery, `curly.toml` configuration, and `curly init`.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Name of the project config file that marks a collection root.
pub const CONFIG_FILE: &str = "curly.toml";
/// Local, git-ignored state directory (history, caches, secret index).
pub const STATE_DIR: &str = ".curly";
/// Directory holding environment files.
pub const ENVS_DIR: &str = "envs";

/// Parsed `curly.toml`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `[project]` section.
    pub project: ProjectSection,
    /// `[curl]` section.
    pub curl: CurlSection,
    /// `[history]` section.
    pub history: HistorySection,
    /// `[redact]` section.
    pub redact: RedactSection,
    /// `[secrets]` section.
    pub secrets: SecretsSection,
}

/// `[project]`: identity and defaults.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectSection {
    /// Human-readable collection name.
    pub name: String,
    /// Random id namespacing keychain entries for this collection.
    pub id: String,
    /// Environment used when `-e` is not given.
    pub default_env: Option<String>,
}

/// `[curl]`: which curl binary to run.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CurlSection {
    /// Path to curl; `CURLY_CURL` overrides it, default is `curl` on `PATH`.
    pub path: Option<String>,
}

/// `[history]`: request logging.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistorySection {
    /// Record every request (default true).
    pub enabled: bool,
    /// Bodies larger than this are truncated in history.
    pub max_body_bytes: usize,
}

impl Default for HistorySection {
    fn default() -> Self {
        HistorySection {
            enabled: true,
            max_body_bytes: 1024 * 1024,
        }
    }
}

/// `[redact]`: what gets masked in history, output, and reports.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedactSection {
    /// Master switch; turning it off is an explicit opt-in to storing secrets.
    pub enabled: bool,
    /// Extra header names to mask (case-insensitive).
    pub headers: Vec<String>,
    /// Extra regex patterns for JSON keys whose values are masked.
    pub json_keys: Vec<String>,
    /// Extra regex patterns for URL query parameter names to mask.
    pub query_params: Vec<String>,
    /// Extra regex patterns for variable names treated as secrets.
    pub variables: Vec<String>,
}

impl Default for RedactSection {
    fn default() -> Self {
        RedactSection {
            enabled: true,
            headers: vec![],
            json_keys: vec![],
            query_params: vec![],
            variables: vec![],
        }
    }
}

/// Where `curly secret` stores values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretBackend {
    /// OS keychain (macOS Keychain, Windows Credential Manager, Linux keyutils).
    #[default]
    Keychain,
    /// Mode-0600 JSON file in `.curly/` (explicit opt-in).
    File,
}

/// `[secrets]`: secret storage backend.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretsSection {
    /// Backend for `curly secret`.
    pub store: SecretBackend,
}

/// A loaded collection: its root directory and configuration.
#[derive(Debug, Clone)]
pub struct Project {
    /// Canonical path of the directory containing `curly.toml`.
    pub root: PathBuf,
    /// Parsed configuration.
    pub config: Config,
}

impl Project {
    /// Finds the nearest `curly.toml` at or above `start` and loads it.
    pub fn discover(start: &Path) -> Result<Project> {
        let start = fs::canonicalize(start)
            .with_context(|| format!("cannot resolve {}", start.display()))?;
        let mut dir: Option<&Path> = Some(if start.is_dir() {
            &start
        } else {
            start.parent().unwrap_or(&start)
        });
        while let Some(d) = dir {
            if d.join(CONFIG_FILE).is_file() {
                return Project::load(d);
            }
            dir = d.parent();
        }
        bail!(
            "no {CONFIG_FILE} found at or above {} (run `curly init`)",
            start.display()
        )
    }

    /// Loads the project rooted at `root`.
    pub fn load(root: &Path) -> Result<Project> {
        let root = fs::canonicalize(root)?;
        let path = root.join(CONFIG_FILE);
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Project { root, config })
    }

    /// Returns `.curly/`, creating it (with a catch-all `.gitignore`) if needed.
    pub fn state_dir(&self) -> Result<PathBuf> {
        ensure_state_dir(&self.root)
    }

    /// Directory with environment files.
    pub fn envs_dir(&self) -> PathBuf {
        self.root.join(ENVS_DIR)
    }

    /// Keychain namespace: the configured id, or the root path as a fallback.
    pub fn keychain_namespace(&self) -> String {
        if self.config.project.id.is_empty() {
            self.root.display().to_string()
        } else {
            self.config.project.id.clone()
        }
    }

    /// Curl binary to run: `CURLY_CURL`, then `[curl] path`, then `curl`.
    pub fn curl_path(&self) -> String {
        std::env::var("CURLY_CURL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| self.config.curl.path.clone())
            .unwrap_or_else(|| "curl".into())
    }

    /// Converts `path` (relative to the current directory or absolute) into a
    /// path relative to the collection root. Fails if it lies outside the root.
    pub fn relative(&self, path: &Path) -> Result<PathBuf> {
        let abs =
            fs::canonicalize(path).with_context(|| format!("cannot find {}", path.display()))?;
        let rel = abs.strip_prefix(&self.root).with_context(|| {
            format!(
                "{} is outside the collection at {}",
                path.display(),
                self.root.display()
            )
        })?;
        Ok(rel.to_path_buf())
    }

    /// Resolves a collection-relative path (as stored in history) to an absolute one.
    pub fn absolute(&self, rel: &Path) -> Result<PathBuf> {
        if rel.components().any(|c| matches!(c, Component::ParentDir)) || rel.is_absolute() {
            bail!(
                "path {} must be relative to the collection root",
                rel.display()
            );
        }
        Ok(self.root.join(rel))
    }
}

/// Creates `.curly/` under `root` with a `.gitignore` that ignores everything.
pub fn ensure_state_dir(root: &Path) -> Result<PathBuf> {
    let dir = root.join(STATE_DIR);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let ignore = dir.join(".gitignore");
    if !ignore.exists() {
        fs::write(&ignore, "*\n")?;
    }
    Ok(dir)
}

/// Generates a random 16-hex-digit project id.
fn new_project_id() -> String {
    let bytes: [u8; 8] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Options for [`init`].
#[derive(Debug, Clone)]
pub struct InitOptions<'a> {
    /// Collection name (default: the directory name).
    pub name: Option<&'a str>,
    /// Default environment name.
    pub env: &'a str,
    /// Also write an example request and a `BASE_URL` in the environment.
    pub sample: bool,
}

impl Default for InitOptions<'_> {
    fn default() -> Self {
        InitOptions {
            name: None,
            env: "local",
            sample: true,
        }
    }
}

/// Scaffolds a collection in `dir`; returns the files created (existing ones are kept).
pub fn init(dir: &Path, opts: &InitOptions<'_>) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(dir)?;
    let env = opts.env;
    let name = opts.name.map(str::to_string).unwrap_or_else(|| {
        fs::canonicalize(dir)
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "collection".into())
    });
    let mut created = Vec::new();
    let mut write_new = |rel: &str, contents: String| -> Result<()> {
        let path = dir.join(rel);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, contents)?;
            created.push(path);
        }
        Ok(())
    };
    let config = format!(
        "[project]\nname = {name:?}\nid = \"{id}\"\ndefault_env = {env:?}\n\n[history]\nenabled = true\n\n[redact]\nenabled = true\n",
        id = new_project_id()
    );
    write_new(CONFIG_FILE, config)?;
    let base_url = if opts.sample {
        "--variable BASE_URL=http://127.0.0.1:8080\n"
    } else {
        ""
    };
    write_new(
        &format!("envs/{env}.curl"),
        format!(
            "# Environment: {env}\n# Run plain curl from the collection root:\n#   curl -K envs/{env}.curl -K path/to/request.curl\n{base_url}"
        ),
    )?;
    write_new("envs/.gitignore", "*.secrets.curl\n".into())?;
    if opts.sample {
        write_new(
            "example.curl",
            "# @name Example request\n# @description Replace me with a real request.\n--expand-url {{BASE_URL}}/health\n--header \"Accept: application/json\"\n".into(),
        )?;
    }
    let state = ensure_state_dir(dir)?;
    created.push(state);
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_then_discover_from_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        let created = init(
            tmp.path(),
            &InitOptions {
                name: Some("demo"),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(created.iter().any(|p| p.ends_with(CONFIG_FILE)));
        fs::create_dir_all(tmp.path().join("a/b")).unwrap();
        let p = Project::discover(&tmp.path().join("a/b")).unwrap();
        assert_eq!(p.config.project.name, "demo");
        assert_eq!(p.config.project.id.len(), 16);
        assert!(p.config.history.enabled);
        assert_eq!(
            fs::read_to_string(tmp.path().join(".curly/.gitignore")).unwrap(),
            "*\n"
        );
    }

    #[test]
    fn init_keeps_existing_files() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(CONFIG_FILE), "[project]\nname = \"keep\"\n").unwrap();
        init(tmp.path(), &InitOptions::default()).unwrap();
        assert!(
            fs::read_to_string(tmp.path().join(CONFIG_FILE))
                .unwrap()
                .contains("keep")
        );
    }

    #[test]
    fn relative_rejects_outside_paths() {
        let tmp = tempfile::tempdir().unwrap();
        init(&tmp.path().join("c"), &InitOptions::default()).unwrap();
        let p = Project::load(&tmp.path().join("c")).unwrap();
        fs::write(tmp.path().join("outside.curl"), "").unwrap();
        assert!(p.relative(&tmp.path().join("outside.curl")).is_err());
        assert_eq!(
            p.relative(&tmp.path().join("c/example.curl")).unwrap(),
            PathBuf::from("example.curl")
        );
        assert!(p.absolute(Path::new("../x")).is_err());
    }

    #[test]
    fn unknown_config_keys_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(CONFIG_FILE), "[project]\nnmae = \"typo\"\n").unwrap();
        assert!(Project::load(tmp.path()).is_err());
    }
}
