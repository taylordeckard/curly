//! Environments, variable definitions, and the curl argument chain that
//! applies them in precedence order.
//!
//! curl keeps the *last* definition of a variable, so curly passes sources from
//! lowest to highest precedence:
//! `-K envs/<env>.curl`, `-K envs/<env>.secrets.curl`, then a generated
//! preamble with keychain secrets and `--var` overrides, then the request file.
//! Secret values reach curl through the child process environment
//! (`variable = %NAME`), never through argv or files curly writes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Serialize;

use crate::curlconf::{self, quote};
use crate::project::Project;
use crate::secrets::{SecretIndex, SecretStore};

/// Variable names that are treated as secrets unless configured otherwise.
static DEFAULT_SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(token|secret|passw|api_?key|credential|private_?key|session|cookie)")
        .expect("regex")
});

/// Secret values shorter than this are not scrubbed from text (too many false hits).
pub const MIN_SECRET_LEN: usize = 4;

/// Where a variable's value comes from, mirroring curl's `--variable` forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Source {
    /// `name=content`.
    Literal {
        /// The literal value.
        value: String,
    },
    /// `name@file` (path relative to the collection root, as curl runs there).
    File {
        /// File path.
        path: String,
    },
    /// `%name`, `%name=default`, or `%name@file`: imported from the process environment.
    Env {
        /// Fallback when the environment variable is unset.
        default: Option<Box<Source>>,
    },
    /// `--expand-variable`: the inner source's text with `{{name}}` references
    /// expanded from the variables defined before it.
    Expanded {
        /// The unexpanded source.
        source: Box<Source>,
    },
}

/// Where a definition was declared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// An environment file.
    Env,
    /// A `*.secrets.curl` file.
    SecretsFile,
    /// The secret store.
    Keychain,
    /// A `_folder.toml` `[vars]` table.
    Folder,
    /// An OAuth access token from a `_folder.toml` `[auth]` table.
    Auth,
    /// Captured from an earlier response in the same run.
    Captured,
    /// A row of a data file.
    Data,
    /// `--var` on the command line.
    Cli,
}

/// Variables layered on top of the environment, besides the secret store.
#[derive(Debug, Clone, Default)]
pub struct Layers {
    /// Folder defaults, farthest first (lowest precedence of all).
    pub folder: Vec<crate::folder::FolderVar>,
    /// OAuth access tokens: `(name, value)`, always secret.
    pub auth: Vec<(String, String)>,
    /// Values captured earlier in the run: `(name, value, secret)`.
    pub captured: Vec<(String, String, bool)>,
    /// Current data row.
    pub data: Vec<(String, String)>,
    /// `--var` overrides (highest precedence).
    pub cli: Vec<(String, String)>,
}

/// A piece of the `-K` chain passed to curl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLayer {
    /// A collection-relative config file.
    File(PathBuf),
    /// Generated config text (written to a private temp file at run time).
    Text(String),
}

/// One variable definition.
#[derive(Debug, Clone, Serialize)]
pub struct VarDef {
    /// Variable name.
    pub name: String,
    /// Value source.
    pub source: Source,
    /// Kind of origin.
    pub origin: Origin,
    /// Human-readable location, e.g. `envs/local.curl:3`.
    pub location: String,
    /// Whether the value must be redacted.
    pub secret: bool,
}

/// Parses a curl `--variable` argument into a name and source.
pub fn parse_variable_arg(arg: &str) -> Result<(String, Source)> {
    let (import, body) = match arg.strip_prefix('%') {
        Some(b) => (true, b),
        None => (false, arg),
    };
    let split = body.find(['=', '@']);
    let name = &body[..split.unwrap_or(body.len())];
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("invalid variable name in `{arg}`");
    }
    let value = split.map(|i| (&body[i..i + 1], &body[i + 1..]));
    let literal_or_file = |v: Option<(&str, &str)>| -> Option<Source> {
        v.map(|(sep, rest)| {
            if sep == "=" {
                Source::Literal { value: rest.into() }
            } else {
                Source::File { path: rest.into() }
            }
        })
    };
    if import {
        Ok((
            name.into(),
            Source::Env {
                default: literal_or_file(value).map(Box::new),
            },
        ))
    } else {
        match literal_or_file(value) {
            Some(s) => Ok((name.into(), s)),
            None => bail!("variable `{arg}` has no value (use name=value, name@file, or %name)"),
        }
    }
}

/// An environment: `envs/<name>.curl` plus an optional `envs/<name>.secrets.curl`.
#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    /// Environment name.
    pub name: String,
    /// Collection-relative env file path.
    pub file: PathBuf,
    /// Collection-relative secrets file path, if present.
    pub secrets_file: Option<PathBuf>,
}

/// Lists environments in `envs/`, sorted by name.
pub fn list_environments(project: &Project) -> Result<Vec<Environment>> {
    let dir = project.envs_dir();
    if !dir.is_dir() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(env) = name
            .strip_suffix(".curl")
            .filter(|n| !n.ends_with(".secrets"))
        {
            out.push(environment(project, env));
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn environment(project: &Project, name: &str) -> Environment {
    let secrets = PathBuf::from(crate::project::ENVS_DIR).join(format!("{name}.secrets.curl"));
    Environment {
        name: name.into(),
        file: PathBuf::from(crate::project::ENVS_DIR).join(format!("{name}.curl")),
        secrets_file: project.root.join(&secrets).is_file().then_some(secrets),
    }
}

/// Finds environment `name`, failing with the list of known ones.
pub fn find_environment(project: &Project, name: &str) -> Result<Environment> {
    let envs = list_environments(project)?;
    envs.iter()
        .find(|e| e.name == name)
        .cloned()
        .with_context(|| {
            let known: Vec<_> = envs.iter().map(|e| e.name.as_str()).collect();
            format!(
                "unknown environment `{name}` (known: {})",
                if known.is_empty() {
                    "none".into()
                } else {
                    known.join(", ")
                }
            )
        })
}

/// Classifies variable names as secret using defaults plus `[redact] variables`.
#[derive(Debug, Clone)]
pub struct SecretNames {
    extra: Vec<Regex>,
}

impl SecretNames {
    /// Builds a classifier from extra regex patterns.
    pub fn new(extra: &[String]) -> Result<SecretNames> {
        let extra = extra
            .iter()
            .map(|p| {
                Regex::new(p).with_context(|| format!("invalid [redact] variables pattern `{p}`"))
            })
            .collect::<Result<_>>()?;
        Ok(SecretNames { extra })
    }

    /// True if `name` should be treated as a secret.
    pub fn is_secret(&self, name: &str) -> bool {
        DEFAULT_SECRET_NAME.is_match(name) || self.extra.iter().any(|r| r.is_match(name))
    }
}

/// A variable's effective value after precedence is applied.
#[derive(Debug, Clone, Serialize)]
pub struct Resolved {
    /// Value as curl will see it, when curly can determine it.
    pub value: Option<String>,
    /// Whether it must be redacted.
    pub secret: bool,
    /// Where the winning definition was declared.
    pub location: String,
}

/// Everything needed to apply variables to one curl invocation.
#[derive(Debug, Clone, Default)]
pub struct VarContext {
    /// Selected environment, if any.
    pub env: Option<Environment>,
    /// Definitions from lowest to highest precedence.
    pub defs: Vec<VarDef>,
    /// Values to place in the child process environment.
    pub child_env: Vec<(String, String)>,
    /// Generated config applied before the environment (folder defaults).
    pub low_preamble: String,
    /// Generated config applied after the environment (secrets, captures, data, `--var`).
    pub preamble: String,
}

impl VarContext {
    /// Adds a generated definition. Secret values go to the child environment
    /// and are imported with `%name`, so they never appear in the preamble.
    fn push_generated(
        &mut self,
        name: &str,
        value: &str,
        origin: Origin,
        location: &str,
        secret: bool,
        high: bool,
    ) {
        let line = if secret {
            self.child_env.retain(|(k, _)| k != name);
            self.child_env.push((name.into(), value.into()));
            format!("variable = %{name}\n")
        } else {
            format!("variable = {}\n", quote(&format!("{name}={value}")))
        };
        if high {
            self.preamble.push_str(&line)
        } else {
            self.low_preamble.push_str(&line)
        }
        self.defs.push(VarDef {
            name: name.into(),
            source: Source::Literal {
                value: value.into(),
            },
            origin,
            location: location.into(),
            secret,
        });
    }

    /// Assembles the variable sources for `env` (or the default environment)
    /// plus folder defaults, captures, data, and `--var` overrides.
    pub fn build(
        project: &Project,
        env: Option<&str>,
        layers: &Layers,
        store: Option<&dyn SecretStore>,
    ) -> Result<VarContext> {
        Self::build_for(project, env, layers, store, None)
    }

    /// Like [`VarContext::build`], but reads from `store` only the secrets in
    /// `needed` (plus those an environment's `--expand-variable` pulls in).
    /// Each keychain read can prompt for the login password, so a request
    /// should not read secrets it never uses. `None` reads every stored secret.
    pub fn build_for(
        project: &Project,
        env: Option<&str>,
        layers: &Layers,
        store: Option<&dyn SecretStore>,
        needed: Option<&BTreeSet<String>>,
    ) -> Result<VarContext> {
        let names = SecretNames::new(&project.config.redact.variables)?;
        let env = match env {
            Some(e) => Some(find_environment(project, e)?),
            None => match &project.config.project.default_env {
                Some(d) => list_environments(project)?
                    .into_iter()
                    .find(|e| &e.name == d),
                None => None,
            },
        };
        let mut ctx = VarContext {
            env: env.clone(),
            low_preamble: "# generated by curly: _folder.toml defaults\n".into(),
            ..Default::default()
        };
        for v in &layers.folder {
            ctx.push_generated(
                &v.name,
                &v.value,
                Origin::Folder,
                &v.location,
                names.is_secret(&v.name),
                false,
            );
        }
        let mut preamble =
            String::from("# generated by curly; secret values arrive via the environment\n");
        if let Some(env) = &env {
            ctx.push_file(project, &env.file, Origin::Env, &names)?;
            if let Some(sf) = &env.secrets_file {
                ctx.push_file(project, sf, Origin::SecretsFile, &names)?;
            }
            if let Some(store) = store {
                let wanted = needed.map(|n| ctx.with_expansion_inputs(n));
                for name in SecretIndex::load(project)?.names(&env.name) {
                    if wanted.as_ref().is_some_and(|w| !w.contains(&name)) {
                        continue;
                    }
                    // An exported shell variable wins over the store, so skip
                    // the (possibly password-prompting) store read entirely.
                    let from_shell = std::env::var_os(&name).is_some();
                    let stored = if from_shell {
                        None
                    } else {
                        store.get(&env.name, &name)?
                    };
                    if from_shell || stored.is_some() {
                        if let Some(value) = stored {
                            ctx.child_env.push((name.clone(), value));
                        }
                        preamble.push_str(&format!("variable = %{name}\n"));
                        ctx.defs.push(VarDef {
                            name: name.clone(),
                            source: Source::Env { default: None },
                            origin: Origin::Keychain,
                            location: store.backend(),
                            secret: true,
                        });
                    }
                }
            }
        }
        ctx.preamble = preamble;
        for (name, value) in &layers.auth {
            ctx.push_generated(name, value, Origin::Auth, "oauth", true, true);
        }
        for (name, value, secret) in &layers.captured {
            ctx.push_generated(
                name,
                value,
                Origin::Captured,
                "capture",
                *secret || names.is_secret(name),
                true,
            );
        }
        for (name, value) in &layers.data {
            ctx.push_generated(
                name,
                value,
                Origin::Data,
                "data row",
                names.is_secret(name),
                true,
            );
        }
        for (name, value) in &layers.cli {
            ctx.push_generated(
                name,
                value,
                Origin::Cli,
                "--var",
                names.is_secret(name),
                true,
            );
        }
        Ok(ctx)
    }

    fn push_file(
        &mut self,
        project: &Project,
        rel: &Path,
        origin: Origin,
        names: &SecretNames,
    ) -> Result<()> {
        let cfg = curlconf::parse_file(&project.root.join(rel))?;
        for e in &cfg.entries {
            let expand = match e.long_name() {
                "variable" => false,
                "expand-variable" => true,
                _ => continue,
            };
            let Some(arg) = &e.value else { continue };
            let (name, source) =
                parse_variable_arg(arg).with_context(|| format!("{}:{}", rel.display(), e.line))?;
            let refs_secret = expand
                && curlconf::var_refs(arg)
                    .iter()
                    .any(|r| names.is_secret(r) || self.defs.iter().any(|d| &d.name == r && d.secret));
            let source = if expand {
                Source::Expanded { source: Box::new(source) }
            } else {
                source
            };
            let secret = origin == Origin::SecretsFile || names.is_secret(&name) || refs_secret;
            self.defs.push(VarDef {
                name,
                source,
                origin: origin.clone(),
                location: format!("{}:{}", rel.display(), e.line),
                secret,
            });
        }
        Ok(())
    }

    /// Config files from the environment (collection-relative).
    pub fn config_files(&self) -> Vec<PathBuf> {
        let mut v = Vec::new();
        if let Some(env) = &self.env {
            v.push(env.file.clone());
            v.extend(env.secrets_file.clone());
        }
        v
    }

    /// The full `-K` chain before the request file, lowest precedence first.
    pub fn layers(&self) -> Vec<ConfigLayer> {
        let mut v = vec![ConfigLayer::Text(self.low_preamble.clone())];
        v.extend(self.config_files().into_iter().map(ConfigLayer::File));
        v.push(ConfigLayer::Text(self.preamble.clone()));
        v
    }

    /// Effective values as strings (unknown values omitted), for `{{var}}` templating.
    pub fn values(&self, root: &Path) -> BTreeMap<String, String> {
        self.effective(root)
            .into_iter()
            .filter_map(|(k, r)| r.value.map(|v| (k, v)))
            .collect()
    }

    /// Names of all defined variables.
    pub fn defined_names(&self) -> Vec<String> {
        let mut v: Vec<_> = self.defs.iter().map(|d| d.name.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Effective values, applying curl's last-definition-wins rule.
    pub fn effective(&self, root: &Path) -> BTreeMap<String, Resolved> {
        self.defs
            .iter()
            .zip(self.resolved_in_order(root))
            .map(|(d, value)| {
                (
                    d.name.clone(),
                    Resolved {
                        value,
                        secret: d.secret,
                        location: d.location.clone(),
                    },
                )
            })
            .collect()
    }

    /// `(name, value)` pairs for every secret with a known value.
    pub fn secret_values(&self, root: &Path) -> Vec<(String, String)> {
        self.defs
            .iter()
            .zip(self.resolved_in_order(root))
            .filter(|(d, _)| d.secret)
            .filter_map(|(d, v)| v.map(|v| (d.name.clone(), v)))
            .collect()
    }

    /// `names` plus every variable that a needed `--expand-variable` definition
    /// references, transitively (e.g. `API_KEY={{DEV_API_KEY}}` needs `DEV_API_KEY`).
    fn with_expansion_inputs(&self, names: &BTreeSet<String>) -> BTreeSet<String> {
        let mut out = names.clone();
        loop {
            let before = out.len();
            for d in &self.defs {
                if let Source::Expanded { source } = &d.source
                    && out.contains(&d.name)
                    && let Source::Literal { value } = source.as_ref()
                {
                    out.extend(curlconf::var_refs(value));
                }
            }
            if out.len() == before {
                return out;
            }
        }
    }

    /// Each definition's value, in definition order, so `--expand-variable`
    /// sees exactly the variables curl has defined before it.
    fn resolved_in_order(&self, root: &Path) -> Vec<Option<String>> {
        let child: BTreeMap<_, _> = self.child_env.iter().cloned().collect();
        let getenv = |n: &str| child.get(n).cloned().or_else(|| std::env::var(n).ok());
        let mut known = BTreeMap::new();
        self.defs
            .iter()
            .map(|d| {
                let value = resolve_source(&d.name, &d.source, root, &getenv, &known);
                match &value {
                    Some(v) => known.insert(d.name.clone(), v.clone()),
                    None => known.remove(&d.name),
                };
                value
            })
            .collect()
    }
}

/// Resolves a source the way curl would (file paths relative to `root`);
/// `known` holds the variables defined so far, for `--expand-variable`.
fn resolve_source(
    name: &str,
    source: &Source,
    root: &Path,
    getenv: &dyn Fn(&str) -> Option<String>,
    known: &BTreeMap<String, String>,
) -> Option<String> {
    match source {
        Source::Literal { value } => Some(value.clone()),
        Source::File { path } if path == "-" => None,
        Source::File { path } => std::fs::read_to_string(root.join(path)).ok(),
        Source::Env { default } => getenv(name).or_else(|| {
            default
                .as_ref()
                .and_then(|d| resolve_source(name, d, root, getenv, known))
        }),
        Source::Expanded { source } => resolve_source(name, source, root, getenv, known)
            .and_then(|text| curlconf::substitute(&text, known).ok()),
    }
}

/// A variable to add to an environment file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVarSpec {
    /// Name.
    pub name: String,
    /// Literal value, or `None` for a secret imported from the shell or secret store.
    pub value: Option<String>,
    /// Comment written above it (may span lines).
    pub comment: Option<String>,
}

/// Appends variables missing from `envs/<env>.curl` (creating it if needed),
/// in command-line style. Existing definitions are never changed.
/// Returns the collection-relative file and the names added.
pub fn add_env_variables(
    root: &Path,
    env: &str,
    specs: &[EnvVarSpec],
    note: &str,
) -> Result<(PathBuf, Vec<String>)> {
    let rel = PathBuf::from(crate::project::ENVS_DIR).join(format!("{env}.curl"));
    let abs = root.join(&rel);
    let existing = if abs.is_file() {
        std::fs::read_to_string(&abs)?
    } else {
        format!(
            "# Environment: {env}\n# Run plain curl from the collection root:\n#   curl -K {} -K path/to/request.curl\n",
            rel.display()
        )
    };
    let defined: std::collections::BTreeSet<String> = curlconf::parse(&existing)
        .entries
        .iter()
        .filter(|e| e.long_name() == "variable")
        .filter_map(|e| {
            e.value
                .as_deref()
                .and_then(|v| parse_variable_arg(v).ok())
                .map(|(n, _)| n)
        })
        .collect();
    let mut added_text = String::new();
    let mut added = Vec::new();
    for spec in specs.iter().filter(|s| !defined.contains(&s.name)) {
        if added.contains(&spec.name) {
            continue;
        }
        if let Some(c) = &spec.comment {
            for (i, line) in c.lines().enumerate() {
                added_text.push_str(&format!(
                    "{}{line}\n",
                    if i == 0 && !line.starts_with('#') {
                        "# "
                    } else {
                        ""
                    }
                ));
            }
        }
        let line = match &spec.value {
            Some(v) => curlconf::flag_line("variable", Some(&format!("{}={v}", spec.name))),
            None => {
                added_text.push_str(&format!(
                    "# Secret: export {0}=... or run `curly secret set {0} -e {env}`\n",
                    spec.name
                ));
                curlconf::flag_line("variable", Some(&format!("%{}=", spec.name)))
            }
        };
        added_text.push_str(&line);
        added_text.push('\n');
        added.push(spec.name.clone());
    }
    if !added.is_empty() {
        let mut text = existing;
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("\n# {note}\n{added_text}"));
        std::fs::create_dir_all(abs.parent().unwrap_or(root))?;
        std::fs::write(&abs, text)?;
    }
    Ok((rel, added))
}

/// Parses `--var name=value` arguments.
pub fn parse_cli_vars(args: &[String]) -> Result<Vec<(String, String)>> {
    args.iter()
        .map(|a| {
            let (k, v) = a
                .split_once('=')
                .with_context(|| format!("--var `{a}` must be name=value"))?;
            if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                bail!("invalid variable name `{k}`");
            }
            Ok((k.to_string(), v.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::FileStore;

    #[test]
    fn parses_variable_forms() {
        assert_eq!(
            parse_variable_arg("A=1").unwrap(),
            ("A".into(), Source::Literal { value: "1".into() })
        );
        assert_eq!(
            parse_variable_arg("A=x=y").unwrap().1,
            Source::Literal {
                value: "x=y".into()
            }
        );
        assert_eq!(
            parse_variable_arg("B@f.txt").unwrap().1,
            Source::File {
                path: "f.txt".into()
            }
        );
        assert_eq!(
            parse_variable_arg("%C").unwrap().1,
            Source::Env { default: None }
        );
        assert_eq!(
            parse_variable_arg("%C=d").unwrap().1,
            Source::Env {
                default: Some(Box::new(Source::Literal { value: "d".into() }))
            }
        );
        assert!(parse_variable_arg("NOVALUE").is_err());
        assert!(parse_variable_arg("bad-name=1").is_err());
    }

    #[test]
    fn secret_names() {
        let n = SecretNames::new(&["^MY_".into()]).unwrap();
        for s in [
            "API_TOKEN",
            "client_secret",
            "DB_PASSWORD",
            "apikey",
            "MY_THING",
        ] {
            assert!(n.is_secret(s), "{s}");
        }
        for s in ["BASE_URL", "user_id", "AUTH_BASE"] {
            assert!(!n.is_secret(s), "{s}");
        }
    }

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
        std::fs::write(
            tmp.path().join("envs/local.curl"),
            "variable = \"BASE_URL=http://h\"\nvariable = \"user_id=1\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("envs/local.secrets.curl"),
            "variable = \"PLAIN_NAME=s3cr3t-value\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("envs/prod.curl"),
            "variable = \"BASE_URL=https://p\"\n",
        )
        .unwrap();
        let p = Project::load(tmp.path()).unwrap();
        (tmp, p)
    }

    #[test]
    fn builds_context_with_precedence() {
        let (tmp, p) = project();
        let store = FileStore::new(tmp.path().join("s.json"));
        store.set("local", "API_TOKEN", "tok-from-store").unwrap();
        SecretIndex::load(&p)
            .unwrap()
            .update("local", "API_TOKEN", true)
            .unwrap();
        let ctx = VarContext::build(
            &p,
            None,
            &Layers {
                cli: vec![
                    ("user_id".into(), "2".into()),
                    ("X_TOKEN".into(), "cli-secret".into()),
                ],
                ..Default::default()
            },
            Some(&store),
        )
        .unwrap();
        assert_eq!(ctx.env.as_ref().unwrap().name, "local");
        assert_eq!(
            ctx.config_files(),
            vec![
                PathBuf::from("envs/local.curl"),
                PathBuf::from("envs/local.secrets.curl")
            ]
        );
        let eff = ctx.effective(&p.root);
        assert_eq!(eff["user_id"].value.as_deref(), Some("2"));
        assert!(eff["PLAIN_NAME"].secret);
        assert!(
            !ctx.preamble.contains("cli-secret"),
            "secret values must not be in the preamble"
        );
        assert!(!ctx.preamble.contains("tok-from-store"));
        assert!(ctx.preamble.contains("variable = %X_TOKEN"));
        assert!(ctx.preamble.contains("variable = \"user_id=2\""));
        let secrets: Vec<_> = ctx
            .secret_values(&p.root)
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        assert!(secrets.contains(&"s3cr3t-value".to_string()));
        assert!(secrets.contains(&"cli-secret".to_string()));
        assert!(
            secrets.contains(&"tok-from-store".to_string())
                || std::env::var_os("API_TOKEN").is_some()
        );
    }

    /// A store that records which secrets were read.
    struct RecordingStore {
        inner: FileStore,
        reads: std::cell::RefCell<Vec<String>>,
    }

    impl SecretStore for RecordingStore {
        fn get(&self, env: &str, name: &str) -> Result<Option<String>> {
            self.reads.borrow_mut().push(name.to_string());
            self.inner.get(env, name)
        }
        fn set(&self, env: &str, name: &str, value: &str) -> Result<()> {
            self.inner.set(env, name, value)
        }
        fn delete(&self, env: &str, name: &str) -> Result<bool> {
            self.inner.delete(env, name)
        }
        fn backend(&self) -> String {
            self.inner.backend()
        }
    }

    #[test]
    fn reads_only_needed_secrets_including_expansion_inputs() {
        let (tmp, p) = project();
        std::fs::write(
            tmp.path().join("envs/local.curl"),
            "--variable %SOURCE_KEY=\n--expand-variable API_KEY={{SOURCE_KEY}}\n",
        )
        .unwrap();
        let store = RecordingStore {
            inner: FileStore::new(tmp.path().join("s.json")),
            reads: Default::default(),
        };
        let mut index = SecretIndex::load(&p).unwrap();
        for name in ["SOURCE_KEY", "UNUSED_TOKEN"] {
            store.set("local", name, "value-of-a-secret").unwrap();
            index.update("local", name, true).unwrap();
        }
        let needed = BTreeSet::from(["API_KEY".to_string()]);
        VarContext::build_for(&p, None, &Layers::default(), Some(&store), Some(&needed)).unwrap();
        assert_eq!(*store.reads.borrow(), vec!["SOURCE_KEY".to_string()]);

        store.reads.borrow_mut().clear();
        VarContext::build(&p, None, &Layers::default(), Some(&store)).unwrap();
        assert_eq!(store.reads.borrow().len(), 2, "without a request, every secret is read");
    }

    #[test]
    fn exported_shell_variable_skips_the_store() {
        let (tmp, p) = project();
        let store = RecordingStore {
            inner: FileStore::new(tmp.path().join("s.json")),
            reads: Default::default(),
        };
        let name = "CURLY_TEST_SHELL_WINS_TOKEN";
        store.set("local", name, "stored-value").unwrap();
        SecretIndex::load(&p).unwrap().update("local", name, true).unwrap();
        // SAFETY: the name is unique to this test, so no other thread reads it.
        unsafe { std::env::set_var(name, "shell-value") };
        let ctx = VarContext::build(&p, None, &Layers::default(), Some(&store)).unwrap();
        unsafe { std::env::remove_var(name) };
        assert!(store.reads.borrow().is_empty(), "store must not be read");
        assert!(ctx.preamble.contains(&format!("variable = %{name}")));
        assert!(!ctx.child_env.iter().any(|(k, _)| k == name));
    }

    #[test]
    fn unknown_environment_lists_known() {
        let (_tmp, p) = project();
        let err = VarContext::build(&p, Some("nope"), &Layers::default(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("local, prod"), "{err}");
    }

    #[test]
    fn layers_apply_in_precedence_order() {
        let (_tmp, p) = project();
        let folder = |name: &str, value: &str| crate::folder::FolderVar {
            name: name.into(),
            value: value.into(),
            location: "_folder.toml".into(),
        };
        let layers = Layers {
            folder: vec![folder("user_id", "from-folder"), folder("only_folder", "f")],
            captured: vec![
                ("cap".into(), "c1".into(), false),
                ("hidden".into(), "captured-secret".into(), true),
            ],
            data: vec![("cap".into(), "from-data".into())],
            auth: vec![
                ("OAUTH_TOK".into(), "oauth-value".into()),
                ("BEATEN".into(), "oauth-value".into()),
            ],
            cli: vec![("BEATEN".into(), "from-cli".into())],
        };
        let ctx = VarContext::build(&p, None, &layers, None).unwrap();
        let v = ctx.values(&p.root);
        assert_eq!(v["OAUTH_TOK"], "oauth-value");
        assert_eq!(v["BEATEN"], "from-cli", "--var beats OAuth tokens");
        assert!(
            !ctx.preamble.contains("oauth-value"),
            "tokens arrive via the environment"
        );
        assert!(
            ctx.secret_values(&p.root)
                .iter()
                .any(|(k, _)| k == "OAUTH_TOK")
        );
        assert_eq!(v["user_id"], "1", "environment beats folder defaults");
        assert_eq!(v["only_folder"], "f");
        assert_eq!(v["cap"], "from-data", "data rows beat captures");
        assert!(ctx.low_preamble.contains("only_folder=f"));
        assert!(!ctx.preamble.contains("captured-secret"));
        let chain = ctx.layers();
        assert!(matches!(&chain[0], ConfigLayer::Text(t) if t.contains("only_folder")));
        assert_eq!(
            chain[1],
            ConfigLayer::File(PathBuf::from("envs/local.curl"))
        );
        assert!(matches!(chain.last().unwrap(), ConfigLayer::Text(t) if t.contains("from-data")));
    }
}
