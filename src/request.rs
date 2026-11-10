//! Running one request file end to end: variables, curl, redaction, history.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

use crate::assertions::Outcome;
use crate::curlconf::{RequestSpec, var_refs};
use crate::curlexec::{Curl, Exchange, Invocation, shell_join};
use crate::folder::{self, folder_vars};
use crate::history::{History, NewEntry};
use crate::lint::{Level, LintContext, lint_request};
use crate::oauth;
use crate::project::Project;
use crate::redact::Redactor;
use crate::secrets::open_store;
use crate::vars::{ConfigLayer, Layers, Origin, SecretNames, VarContext};

/// Options for [`run_request`].
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Environment name (default from `curly.toml`).
    pub env: Option<String>,
    /// `--var` overrides.
    pub vars: Vec<(String, String)>,
    /// Values captured earlier in the run: `(name, value, secret)`.
    pub captured: Vec<(String, String, bool)>,
    /// Current data row.
    pub data: Vec<(String, String)>,
    /// Record the exchange in history.
    pub record: bool,
    /// Return the unredacted exchange for display (history stays redacted).
    pub show_secrets: bool,
    /// Send this JSON body (POST) instead of the file's body; used for GraphQL
    /// introspection. Such runs are recorded without a request file.
    pub body_override: Option<String>,
}

/// Result of running a request.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Parsed request file.
    pub spec: RequestSpec,
    /// Exchange for display: redacted unless `show_secrets` was set.
    pub exchange: Exchange,
    /// Unredacted exchange, for assertions and captures only.
    pub raw: Exchange,
    /// Effective variable values (unredacted), for templated expectations.
    pub vars: BTreeMap<String, String>,
    /// Redactor built from this request's secrets.
    pub redactor: Redactor,
    /// Environment used.
    pub env: Option<String>,
    /// History id, if recorded.
    pub history_id: Option<i64>,
    /// Checks already evaluated during the run (WebSocket steps).
    pub outcome: Option<Outcome>,
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Opens the project's history database.
pub fn open_history(project: &Project) -> Result<History> {
    History::open(&project.state_dir()?.join("history.db"))
}

/// Builds the variable context for `rel` (folder defaults included when given).
/// For a request file, only the secrets it can use are read from the store.
pub fn var_context(
    project: &Project,
    rel: Option<&Path>,
    env: Option<&str>,
    layers: Layers,
) -> Result<VarContext> {
    let store = open_store(project)?;
    let needed = rel
        .filter(|r| project.root.join(r).is_file())
        .map(|r| referenced_names(project, r))
        .transpose()?;
    let layers = Layers {
        folder: rel
            .map(|r| folder_vars(project, r))
            .transpose()?
            .unwrap_or_default(),
        ..layers
    };
    VarContext::build_for(project, env, &layers, Some(store.as_ref()), needed.as_ref())
}

/// Variables request file `rel` can use: its `{{name}}` references and
/// `--variable %name` imports, plus references in the `_folder.toml` files
/// above it (where `[auth]` settings live).
fn referenced_names(project: &Project, rel: &Path) -> Result<BTreeSet<String>> {
    let text = std::fs::read_to_string(project.root.join(rel))?;
    let spec = RequestSpec::from_config(rel.to_path_buf(), crate::curlconf::parse(&text));
    let mut names: BTreeSet<String> = var_refs(&text).into_iter().collect();
    names.extend(spec.variables.iter().filter_map(|(_, arg)| {
        match crate::vars::parse_variable_arg(arg).ok()? {
            (name, crate::vars::Source::Env { .. }) => Some(name),
            _ => None,
        }
    }));
    for (path, _) in folder::chain(project, rel)? {
        names.extend(var_refs(&std::fs::read_to_string(project.root.join(path))?));
    }
    Ok(names)
}

/// Fails if the request is not runnable as a single request with all variables defined.
fn preflight(spec: &RequestSpec, ctx: &VarContext) -> Result<()> {
    let lint_ctx = LintContext {
        catalog: None,
        defined: ctx.defined_names().into_iter().collect::<BTreeSet<_>>(),
        env_name: ctx.env.as_ref().map(|e| e.name.clone()),
    };
    let blocking: Vec<String> = lint_request(spec, &lint_ctx)
        .into_iter()
        .filter(|d| {
            d.level == Level::Error
                && ["not defined", "exactly one", "no `url`", "unterminated"]
                    .iter()
                    .any(|m| d.message.contains(m))
        })
        .map(|d| d.to_string())
        .collect();
    if !blocking.is_empty() {
        bail!("{}", blocking.join("\n"));
    }
    Ok(())
}

/// Runs `rel` (collection-relative) and returns the exchange.
pub fn run_request(
    project: &Project,
    curl: &Curl,
    rel: &Path,
    opts: &RunOptions,
) -> Result<RunResult> {
    let Prepared { spec, source, ctx } = prepare(project, curl, rel, opts)?;
    if opts.body_override.is_none()
        && let Ok(Some(check)) =
            crate::graphql::check_request(project, &spec, &ctx.values(&project.root))
    {
        for d in &check.diagnostics {
            eprintln!(
                "warning: {}: {} (schema cached for {}; refresh with `curly gql introspect {}`)",
                d.location(&check.document),
                d.message,
                check.endpoint,
                rel.display()
            );
        }
    }
    let inv = Invocation {
        root: project.root.clone(),
        layers: ctx.layers(),
        request: match &opts.body_override {
            None => ConfigLayer::File(rel.to_path_buf()),
            Some(body) => ConfigLayer::Text(format!(
                "{}request = \"POST\"\nheader = \"Content-Type: application/json\"\ndata-binary = {}\n",
                crate::curlconf::render_without(
                    &spec.config,
                    &[crate::curlconf::BODY_OPTIONS, &["request", "head"]].concat()
                ),
                crate::curlconf::quote(body)
            )),
        },
        child_env: ctx.child_env.clone(),
    };
    let raw = inv.execute(curl)?;
    finish(
        project,
        rel,
        Prepared { spec, source, ctx },
        raw,
        opts,
        None,
        vec![],
    )
}

/// A request file with its variables resolved (OAuth tokens included).
pub struct Prepared {
    /// Parsed request.
    pub spec: RequestSpec,
    /// File bytes (hashed into history).
    pub source: Vec<u8>,
    /// Variables for this run.
    pub ctx: VarContext,
}

/// Loads `rel`, resolves its variables, and fetches an OAuth token when an
/// `[auth]` applies and no capture, data row, or `--var` already provides it.
pub fn prepare(project: &Project, curl: &Curl, rel: &Path, opts: &RunOptions) -> Result<Prepared> {
    let source = std::fs::read(project.absolute(rel)?)?;
    let spec = RequestSpec::from_config(
        rel.to_path_buf(),
        crate::curlconf::parse(&String::from_utf8_lossy(&source)),
    );
    let mut layers = Layers {
        captured: opts.captured.clone(),
        data: opts.data.clone(),
        cli: opts.vars.clone(),
        ..Default::default()
    };
    let mut ctx = var_context(project, Some(rel), opts.env.as_deref(), layers.clone())?;
    if let Some(auth) = oauth::resolve(project, rel, &ctx)? {
        let token_var = auth.cfg.token_var.clone();
        let overridden = ctx.defs.iter().any(|d| {
            d.name == token_var && matches!(d.origin, Origin::Cli | Origin::Captured | Origin::Data)
        });
        if !overridden {
            let token = oauth::access_token(project, curl, &auth, oauth::interactive())?;
            layers.auth = vec![(token_var, token)];
            ctx = var_context(project, Some(rel), opts.env.as_deref(), layers)?;
        }
    }
    preflight(&spec, &ctx)?;
    Ok(Prepared { spec, source, ctx })
}

/// Redacts `raw`, records it in history, and builds the result. `extra_secrets`
/// are values learned during the run (e.g. captured in a WebSocket session).
pub fn finish(
    project: &Project,
    rel: &Path,
    prepared: Prepared,
    raw: Exchange,
    opts: &RunOptions,
    outcome: Option<Outcome>,
    extra_secrets: Vec<(String, String)>,
) -> Result<RunResult> {
    let Prepared { spec, source, ctx } = prepared;
    let mut secrets = ctx.secret_values(&project.root);
    secrets.extend(extra_secrets);
    let redactor = Redactor::new(&project.config.redact, secrets)?;
    let redacted = redactor.exchange(&raw);
    let redact_history = project.config.redact.enabled;
    let history_id = if opts.record && project.config.history.enabled {
        let names = SecretNames::new(&project.config.redact.variables)?;
        let vars: BTreeMap<String, Option<String>> = opts
            .vars
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    if names.is_secret(k) && redact_history {
                        None
                    } else {
                        Some(v.clone())
                    },
                )
            })
            .collect();
        let meta = NewEntry {
            file: opts
                .body_override
                .is_none()
                .then(|| rel.display().to_string()),
            env: ctx.env.as_ref().map(|e| e.name.clone()),
            vars,
            file_sha256: Some(sha256_hex(&source)),
            redacted: redact_history,
        };
        let stored = if redact_history { &redacted } else { &raw };
        Some(open_history(project)?.insert(&meta, stored, project.config.history.max_body_bytes)?)
    } else {
        None
    };
    let exchange = if opts.show_secrets || !redact_history {
        raw.clone()
    } else {
        redacted
    };
    Ok(RunResult {
        spec,
        exchange,
        raw,
        vars: ctx.values(&project.root),
        redactor,
        env: ctx.env.as_ref().map(|e| e.name.clone()),
        history_id,
        outcome,
    })
}

/// Whether `rel` is a WebSocket request file.
pub fn is_ws(rel: &Path) -> bool {
    rel.extension().is_some_and(|e| e == "ws")
}

/// Runs any request file: `.curl` through curl, `.ws` as a scripted WebSocket session, `.grpc` as a gRPC call.
pub fn run_any(project: &Project, curl: &Curl, rel: &Path, opts: &RunOptions) -> Result<RunResult> {
    if is_ws(rel) {
        crate::ws::run(project, curl, rel, opts)
    } else if is_grpc(rel) {
        crate::grpc::run(project, curl, rel, opts)
    } else {
        run_request(project, curl, rel, opts)
    }
}

/// Whether `rel` is a gRPC request file.
pub fn is_grpc(rel: &Path) -> bool {
    rel.extension().is_some_and(|e| e == "grpc")
}

/// The plain-curl command equivalent to running `rel`, plus the shell
/// `export` lines needed for secrets and OAuth tokens.
pub fn plain_command(
    project: &Project,
    rel: &Path,
    env: Option<&str>,
    vars: &[(String, String)],
) -> Result<(String, Vec<String>)> {
    let ctx = var_context(
        project,
        Some(rel),
        env,
        Layers {
            cli: vars.to_vec(),
            ..Default::default()
        },
    )?;
    let env_name = ctx.env.as_ref().map(|e| e.name.clone()).unwrap_or_default();
    let mut args: Vec<String> = vec!["curl".into()];
    let mut exports = Vec::new();
    let mut push_def = |args: &mut Vec<String>, d: &crate::vars::VarDef| {
        if d.secret {
            args.extend(["--variable".into(), format!("%{}", d.name)]);
            exports.push(match d.origin {
                Origin::Keychain => format!(
                    "export {0}=\"$(curly secret get {0} -e {env_name})\"",
                    d.name
                ),
                _ => format!("export {}=...   # the value you passed with --var", d.name),
            });
        } else if let crate::vars::Source::Literal { value } = &d.source {
            args.extend(["--variable".into(), format!("{}={value}", d.name)]);
        }
    };
    for d in ctx.defs.iter().filter(|d| d.origin == Origin::Folder) {
        push_def(&mut args, d);
    }
    for f in ctx.config_files() {
        args.extend(["-K".into(), f.display().to_string()]);
    }
    for d in ctx
        .defs
        .iter()
        .filter(|d| matches!(d.origin, Origin::Keychain | Origin::Cli))
    {
        push_def(&mut args, d);
    }
    if let Some((folder, auth)) = oauth::find(project, rel)? {
        let folder = if folder.as_os_str().is_empty() {
            ".".to_string()
        } else {
            folder.display().to_string()
        };
        exports.push(format!(
            "export {}=\"$(curly auth token {folder} -e {env_name})\"",
            auth.token_var
        ));
        args.extend(["--variable".into(), format!("%{}", auth.token_var)]);
    }
    args.extend(["-K".into(), rel.display().to_string()]);
    Ok((shell_join(&args), exports))
}
