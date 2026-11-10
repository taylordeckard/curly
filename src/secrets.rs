//! Secret storage for `curly secret`: the OS keychain by default, or an
//! opt-in mode-0600 file. Values never go into request files, history, or reports.
//!
//! Keychains cannot enumerate entries, so the *names* of stored secrets are
//! kept in `.curly/secrets.json`. That file never contains values.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::project::{Project, SecretBackend};

/// Keychain service name for all curly entries.
const KEYCHAIN_SERVICE: &str = "curly";

/// A place to keep secret values, keyed by environment and variable name.
pub trait SecretStore {
    /// Returns the stored value, if any.
    fn get(&self, env: &str, name: &str) -> Result<Option<String>>;
    /// Stores a value, replacing any existing one.
    fn set(&self, env: &str, name: &str, value: &str) -> Result<()>;
    /// Deletes a value; returns whether it existed.
    fn delete(&self, env: &str, name: &str) -> Result<bool>;
    /// Short backend description for messages.
    fn backend(&self) -> String;
}

/// OS keychain store, namespaced by project id.
pub struct KeychainStore {
    namespace: String,
}

impl KeychainStore {
    fn entry(&self, env: &str, name: &str) -> Result<keyring::Entry> {
        Ok(keyring::Entry::new(
            KEYCHAIN_SERVICE,
            &format!("{}/{env}/{name}", self.namespace),
        )?)
    }
}

impl SecretStore for KeychainStore {
    fn get(&self, env: &str, name: &str) -> Result<Option<String>> {
        match self.entry(env, name)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e).context("reading from the OS keychain"),
        }
    }

    fn set(&self, env: &str, name: &str, value: &str) -> Result<()> {
        self.entry(env, name)?
            .set_password(value)
            .context("writing to the OS keychain")
    }

    fn delete(&self, env: &str, name: &str) -> Result<bool> {
        match self.entry(env, name)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(e).context("deleting from the OS keychain"),
        }
    }

    fn backend(&self) -> String {
        "OS keychain".into()
    }
}

/// JSON file store (`{env: {name: value}}`) written with mode 0600.
pub struct FileStore {
    path: PathBuf,
}

type FileData = BTreeMap<String, BTreeMap<String, String>>;

impl FileStore {
    /// Creates a store backed by the JSON file at `path`.
    pub fn new(path: PathBuf) -> FileStore {
        FileStore { path }
    }

    fn read(&self) -> Result<FileData> {
        match fs::read_to_string(&self.path) {
            Ok(s) => Ok(serde_json::from_str(&s)
                .with_context(|| format!("parsing {}", self.path.display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileData::new()),
            Err(e) => Err(e.into()),
        }
    }

    fn write(&self, data: &FileData) -> Result<()> {
        write_private(&self.path, serde_json::to_string_pretty(data)?.as_bytes())
    }
}

impl SecretStore for FileStore {
    fn get(&self, env: &str, name: &str) -> Result<Option<String>> {
        Ok(self.read()?.get(env).and_then(|m| m.get(name)).cloned())
    }

    fn set(&self, env: &str, name: &str, value: &str) -> Result<()> {
        let mut data = self.read()?;
        data.entry(env.into())
            .or_default()
            .insert(name.into(), value.into());
        self.write(&data)
    }

    fn delete(&self, env: &str, name: &str) -> Result<bool> {
        let mut data = self.read()?;
        let existed = data.get_mut(env).and_then(|m| m.remove(name)).is_some();
        self.write(&data)?;
        Ok(existed)
    }

    fn backend(&self) -> String {
        format!("file {}", self.path.display())
    }
}

/// Writes `bytes` to `path`, creating it with mode 0600 on Unix.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

/// Opens the configured store. `CURLY_SECRET_STORE=file:<path>` or
/// `=keychain` overrides `[secrets] store`.
pub fn open_store(project: &Project) -> Result<Box<dyn SecretStore>> {
    if let Ok(spec) = std::env::var("CURLY_SECRET_STORE") {
        if let Some(path) = spec.strip_prefix("file:") {
            return Ok(Box::new(FileStore {
                path: PathBuf::from(path),
            }));
        }
        if spec == "keychain" {
            return Ok(Box::new(KeychainStore {
                namespace: project.keychain_namespace(),
            }));
        }
    }
    Ok(match project.config.secrets.store {
        SecretBackend::Keychain => Box::new(KeychainStore {
            namespace: project.keychain_namespace(),
        }),
        SecretBackend::File => Box::new(FileStore {
            path: project.state_dir()?.join("secrets.store.json"),
        }),
    })
}

/// Names (never values) of stored secrets per environment, in `.curly/secrets.json`.
#[derive(Debug, Default)]
pub struct SecretIndex {
    path: PathBuf,
    /// Environment -> secret names.
    pub envs: BTreeMap<String, BTreeSet<String>>,
}

impl SecretIndex {
    /// Loads the index for `project` (empty if absent).
    pub fn load(project: &Project) -> Result<SecretIndex> {
        let path = project.state_dir()?.join("secrets.json");
        let envs = match fs::read_to_string(&path) {
            Ok(s) => {
                serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(SecretIndex { path, envs })
    }

    /// Names stored for `env`.
    pub fn names(&self, env: &str) -> Vec<String> {
        self.envs
            .get(env)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Records or forgets a name and saves the index.
    pub fn update(&mut self, env: &str, name: &str, present: bool) -> Result<()> {
        let set = self.envs.entry(env.into()).or_default();
        if present {
            set.insert(name.into());
        } else {
            set.remove(name);
        }
        fs::write(&self.path, serde_json::to_string_pretty(&self.envs)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_roundtrip_and_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore {
            path: tmp.path().join("s.json"),
        };
        assert_eq!(store.get("local", "TOKEN").unwrap(), None);
        store.set("local", "TOKEN", "v1").unwrap();
        assert_eq!(store.get("local", "TOKEN").unwrap().as_deref(), Some("v1"));
        assert!(store.delete("local", "TOKEN").unwrap());
        assert!(!store.delete("local", "TOKEN").unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(tmp.path().join("s.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
