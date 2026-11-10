//! Command-line interface.

use std::collections::BTreeSet;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Local, Utc};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::engine::{ArgValueCandidates, ArgValueCompleter, PathCompleter};
use clap_complete::env::{CompleteEnv, Shells};

use crate::completion;

use crate::assertions::{self, TestFile};
use crate::curlconf::{OptionCatalog, RequestSpec, find_requests};
use crate::curlexec::Curl;
use crate::filter::Filter;
use crate::folder;
use crate::history::{self, Entry, Query};
use crate::lint::{Diagnostic, Level, LintContext, lint_request};
use crate::project::{self, Project};
use crate::report;
use crate::request::{RunOptions, open_history, plain_command, run_request, var_context};
use crate::runner::{self, RunnerOptions, StepResult};
use crate::secrets::{SecretIndex, open_store};
use crate::vars::{Layers, SecretNames, list_environments, parse_cli_vars};
use crate::view::{Mode, Paint, ViewOptions, render};

/// Exit code when every request passed.
pub const EXIT_OK: i32 = 0;
/// Exit code for failed checks, lint errors, or differing diffs.
pub const EXIT_FAILED: i32 = 1;
/// Exit code for usage or configuration errors.
pub const EXIT_USAGE: i32 = 2;
/// Exit code when curl could not complete a transfer.
pub const EXIT_TRANSPORT: i32 = 3;

/// API-workbench features on top of curl and plain files.
#[derive(Debug, Parser)]
#[command(name = "curly", version, about, propagate_version = true)]
pub struct Cli {
    /// Run as if started in this directory.
    #[arg(short = 'C', long, global = true, value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create curly.toml, envs/, and .curly/ in a directory.
    Init {
        /// Target directory (default: current).
        dir: Option<PathBuf>,
        /// Collection name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Run request files and show the responses.
    Run(RunArgs),
    /// Turn a curl command into a request file (hosts and credentials become variables).
    New {
        /// Request file to create, e.g. users/create.curl.
        path: PathBuf,
        /// Read the command from stdin (e.g. `pbpaste | curly new x.curl --stdin`).
        #[arg(long)]
        stdin: bool,
        /// `@name` for the request.
        #[arg(long)]
        name: Option<String>,
        /// Keep the URL and credentials exactly as given (lint will flag credentials).
        #[arg(long)]
        literal: bool,
        /// Do not put extracted credentials in the secret store.
        #[arg(long)]
        no_store_secrets: bool,
        /// Environment that receives new variables.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// The curl command, after `--` (e.g. `-- curl -H 'Accept: x' https://...`).
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Run curl arguments as-is, with curly's viewer, history, and redaction.
    /// curly options go first; everything from the first curl argument on is passed to curl.
    /// `-r` stays curl's `--range` here; use `--raw` for raw output.
    #[command(mut_arg("raw", |a| a.short(None)))]
    Curl(CurlArgs),
    /// Rewrite request and environment files in command-line style (`--header "..."`).
    Fmt {
        /// Files or folders (default: the whole collection, including envs/).
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        paths: Vec<PathBuf>,
        /// Only report files that would change (exit 1 if any).
        #[arg(long)]
        check: bool,
    },
    /// Print the equivalent plain curl command for a request.
    Cmd {
        /// Request file.
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        file: PathBuf,
        #[command(flatten)]
        vars: VarArgs,
    },
    /// Check request files for curl validity and collection rules.
    Lint {
        /// Files or folders (default: whole collection).
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        vars: VarArgs,
    },
    /// Generate request files from an API description.
    #[command(subcommand)]
    Import(ImportCommand),
    /// OAuth 2.0 login, tokens, and cache.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// GraphQL: introspect, validate, complete, and generate requests.
    #[command(subcommand)]
    Gql(GqlCommand),
    /// gRPC: list services, describe methods, and create requests.
    #[command(subcommand)]
    Grpc(GrpcCommand),
    /// Open a WebSocket request: run its [[step]] script, or chat interactively with -i.
    Ws {
        /// A .ws request file.
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        file: PathBuf,
        /// Interactive: send lines typed on stdin, print messages as they arrive.
        #[arg(short, long)]
        interactive: bool,
        #[command(flatten)]
        vars: VarArgs,
        /// Plain text: no colors.
        #[arg(long)]
        plain: bool,
        /// Show secrets in output.
        #[arg(long)]
        show_secrets: bool,
        /// Do not record the session in history.
        #[arg(long)]
        no_history: bool,
    },
    /// Inspect environments.
    #[command(subcommand)]
    Env(EnvCommand),
    /// Manage secrets in the OS keychain.
    #[command(subcommand)]
    Secret(SecretCommand),
    /// Browse, diff, and re-run past requests.
    #[command(subcommand)]
    History(HistoryCommand),
    /// Serve mock responses on localhost from an OpenAPI spec and/or saved examples.
    Mock {
        /// OpenAPI 3.x / Swagger 2.0 file.
        #[arg(long, add = ArgValueCompleter::new(completion::spec_files))]
        spec: Option<PathBuf>,
        /// Also serve the collection's *.example.json files (the default without --spec).
        #[arg(long)]
        examples: bool,
        /// Loopback address to bind.
        #[arg(long, default_value = "127.0.0.1")]
        host: std::net::IpAddr,
        /// Port (0 = any free port).
        #[arg(short, long, default_value_t = 4010)]
        port: u16,
        /// Reject requests whose JSON body or required query parameters do not match the spec.
        #[arg(long)]
        validate: bool,
    },
    /// Write a static reference (HTML or Markdown) for the collection to a local folder.
    Docs {
        /// Request files or folders (default: the whole collection).
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        paths: Vec<PathBuf>,
        /// Output format.
        #[arg(long, value_parser = ["html", "md"], default_value = "html")]
        format: String,
        /// Output folder (default: docs/ in the collection root).
        #[arg(short, long, value_name = "DIR", add = ArgValueCompleter::new(PathCompleter::dir()))]
        out: Option<PathBuf>,
        /// Environment whose non-secret values appear in the variables table.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
    /// Browse history in the terminal UI, or open one entry.
    Tui {
        /// Entry id (`last` for the newest); omit to browse.
        #[arg(add = ArgValueCandidates::new(completion::history_ids))]
        id: Option<String>,
    },
    /// Print the shell completion script, e.g. `source <(curly completion zsh)`.
    Completion {
        /// Shell to generate for.
        #[arg(value_parser = ["bash", "zsh", "fish", "elvish", "powershell"])]
        shell: String,
    },
}

/// Environment and variable overrides.
#[derive(Debug, Clone, Args, Default)]
pub struct VarArgs {
    /// Environment from envs/ (default: [project] default_env).
    #[arg(short, long, value_name = "NAME", add = ArgValueCandidates::new(completion::environments))]
    pub env: Option<String>,
    /// Override a variable (repeatable).
    #[arg(long = "var", value_name = "NAME=VALUE", add = ArgValueCompleter::new(completion::variables))]
    pub vars: Vec<String>,
}

/// Response display options.
#[derive(Debug, Clone, Args, Default)]
pub struct ViewArgs {
    /// Print the response body bytes exactly as received.
    #[arg(short, long, group = "mode")]
    pub raw: bool,
    /// Print only the status line and headers.
    #[arg(long, group = "mode")]
    pub headers: bool,
    /// Print only the formatted body.
    #[arg(long, group = "mode")]
    pub body: bool,
    /// Filter the JSON body with a jq expression.
    #[arg(long, value_name = "EXPR", group = "filter")]
    pub jq: Option<String>,
    /// Filter the JSON body with a JSONPath query.
    #[arg(long, value_name = "JSONPATH", group = "filter")]
    pub path: Option<String>,
    /// Plain text: no colors or highlighting.
    #[arg(long)]
    pub plain: bool,
    /// Also show the request and a timing breakdown.
    #[arg(short, long)]
    pub verbose: bool,
    /// Open the response in the terminal UI (collapsible JSON).
    #[arg(long, conflicts_with_all = ["raw", "headers", "body", "jq", "path", "plain"])]
    pub tui: bool,
}

impl ViewArgs {
    fn options(&self) -> ViewOptions {
        let mode = if self.raw {
            Mode::Raw
        } else if self.headers {
            Mode::Headers
        } else if self.body {
            Mode::Body
        } else {
            Mode::Full
        };
        let filter = self
            .jq
            .clone()
            .map(Filter::Jq)
            .or_else(|| self.path.clone().map(Filter::JsonPath));
        ViewOptions {
            mode,
            color: use_color(self.plain),
            verbose: self.verbose,
            filter,
        }
    }
}

/// `curly run` arguments.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Request files and folders (folders run in `_folder.toml` order).
    #[arg(required = true, add = ArgValueCompleter::new(completion::requests))]
    pub paths: Vec<PathBuf>,
    #[command(flatten)]
    pub vars: VarArgs,
    #[command(flatten)]
    pub view: ViewArgs,
    /// Run once per row of this CSV or JSON file (columns become variables).
    #[arg(long, value_name = "FILE", add = ArgValueCompleter::new(completion::data_files))]
    pub data: Option<PathBuf>,
    /// Stop at the first failed check or error.
    #[arg(long)]
    pub bail: bool,
    /// Write a report: junit=PATH or json=PATH (repeatable).
    #[arg(long = "report", value_name = "FORMAT=PATH", add = ArgValueCompleter::new(completion::reports))]
    pub reports: Vec<String>,
    /// In multi-request runs, also print each response.
    #[arg(long)]
    pub responses: bool,
    /// Do not record these requests in history.
    #[arg(long)]
    pub no_history: bool,
    /// Show secrets in output (history and reports stay redacted).
    #[arg(long)]
    pub show_secrets: bool,
}

/// `curly import` subcommands.
#[derive(Debug, Subcommand)]
pub enum ImportCommand {
    /// Import an OpenAPI 3.x or Swagger 2.0 spec (file or URL).
    #[command(alias = "swagger")]
    Openapi {
        /// Spec file path or http(s) URL.
        #[arg(add = ArgValueCompleter::new(completion::spec_files))]
        source: String,
        /// Output folder (default: ./<api-title>); a new collection is created if needed.
        #[arg(short, long, value_name = "DIR", add = ArgValueCompleter::new(PathCompleter::dir()))]
        out: Option<PathBuf>,
        /// Environment that receives BASE_URL and parameter variables.
        #[arg(short, long, default_value = "local", add = ArgValueCandidates::new(completion::environments))]
        env: String,
        /// Overwrite files that already exist.
        #[arg(long)]
        force: bool,
    },
}

/// `curly auth` subcommands. PATH is a folder or request file; its nearest
/// `_folder.toml` `[auth]` is used.
#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Get new tokens now (opens the browser for the authorization code flow).
    Login {
        /// Folder or request file (default: collection root).
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        path: Option<PathBuf>,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
        /// Print the login URL instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
        /// Seconds to wait for the browser redirect.
        #[arg(long, default_value_t = 300)]
        timeout: u64,
    },
    /// Print a valid access token (refreshing it if needed), for use with plain curl.
    Token {
        /// Folder or request file (default: collection root).
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        path: Option<PathBuf>,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
    /// List cached tokens (never their values).
    Status,
    /// Delete cached tokens.
    Logout {
        /// Folder or request file (default: everything with --all).
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        path: Option<PathBuf>,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
        /// Delete every cached token.
        #[arg(long)]
        all: bool,
    },
}

/// `curly gql` subcommands.
#[derive(Debug, Subcommand)]
pub enum GqlCommand {
    /// Fetch and cache the schema of a GraphQL request's endpoint (uses its headers and auth).
    Introspect {
        /// A GraphQL request file.
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        request: PathBuf,
        #[command(flatten)]
        vars: VarArgs,
    },
    /// Validate GraphQL documents and variables against the cached schemas.
    Check {
        /// Request files or folders (default: every GraphQL request).
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        paths: Vec<PathBuf>,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
    /// Print field completions at FILE.graphql:LINE:COL (for editors).
    Complete {
        /// Position, e.g. graphql/get-user.graphql:3:5.
        position: String,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
        /// Output JSON.
        #[arg(long)]
        json: bool,
    },
    /// Create a GraphQL request (.curl, .graphql, .vars.json, .test.toml).
    New {
        /// New request path, e.g. graphql/get-user.
        path: PathBuf,
        /// Root field to call, e.g. Query.user (needs a cached schema).
        #[arg(long, add = ArgValueCompleter::new(completion::graphql_fields))]
        field: Option<String>,
        /// Endpoint URL template.
        #[arg(long, default_value = "{{BASE_URL}}/graphql")]
        url: String,
        /// Extra header with variables, e.g. "Authorization: Bearer {{ACCESS_TOKEN}}" (repeatable).
        #[arg(long = "header")]
        headers: Vec<String>,
        /// Environment used to resolve the endpoint.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },
    /// Print the cached schema of a request's endpoint as SDL.
    Schema {
        /// A GraphQL request file.
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        request: PathBuf,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
}

/// `curly grpc` subcommands. Descriptors come from server reflection unless
/// the request (or `--proto`) names `.proto` files.
#[derive(Debug, Subcommand)]
pub enum GrpcCommand {
    /// List services and methods of a server (a .grpc file or host:port).
    List {
        /// A .grpc request file, or host:port.
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        target: String,
        /// Use TLS when TARGET is host:port.
        #[arg(long)]
        tls: bool,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
    /// Show a request's method signature, message fields, and an example request.
    Describe {
        /// A .grpc request file.
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        request: PathBuf,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
    /// Create a .grpc request (and test sidecar) with an example message.
    New {
        /// New request path, e.g. grpc/get-user.
        path: PathBuf,
        /// Method as package.Service/Method.
        #[arg(long)]
        method: String,
        /// Server address template.
        #[arg(long, default_value = "{{GRPC_TARGET}}")]
        target: String,
        /// Use .proto files instead of reflection (repeatable, collection-relative).
        #[arg(long)]
        proto: Vec<PathBuf>,
        /// Metadata header with variables, e.g. "authorization: Bearer {{API_TOKEN}}" (repeatable).
        #[arg(long = "header")]
        headers: Vec<String>,
        /// Use TLS (grpcs://).
        #[arg(long)]
        tls: bool,
        /// Environment used to resolve the target.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },
}

/// `curly curl` arguments.
#[derive(Debug, Args)]
pub struct CurlArgs {
    #[command(flatten)]
    pub view: ViewArgs,
    /// Save the command as this request file (templated like `curly new`), then run it.
    #[arg(long, value_name = "FILE")]
    pub save: Option<PathBuf>,
    /// Environment (only used inside a collection).
    #[arg(long, add = ArgValueCandidates::new(completion::environments))]
    pub env: Option<String>,
    /// Do not record the request in history.
    #[arg(long)]
    pub no_history: bool,
    /// Show secrets in output.
    #[arg(long)]
    pub show_secrets: bool,
    /// curl arguments, exactly as you would pass them to curl.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true,
        value_name = "CURL ARGS"
    )]
    pub args: Vec<String>,
}

/// `curly env` subcommands.
#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// List environments.
    List,
    /// Show variables and where each comes from.
    Vars {
        /// Include `_folder.toml` defaults that apply to this request file.
        #[arg(add = ArgValueCompleter::new(completion::requests))]
        file: Option<PathBuf>,
        #[command(flatten)]
        vars: VarArgs,
        /// Show secret values.
        #[arg(long)]
        show_secrets: bool,
    },
}

/// `curly secret` subcommands.
#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Store a secret; the value is read from a prompt or stdin, never argv.
    Set {
        /// Variable name.
        name: String,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
    /// Print a stored secret.
    Get {
        /// Variable name.
        #[arg(add = ArgValueCandidates::new(completion::secret_names))]
        name: String,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
    /// Delete a stored secret.
    Rm {
        /// Variable name.
        #[arg(add = ArgValueCandidates::new(completion::secret_names))]
        name: String,
        /// Environment.
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
    /// List stored secret names.
    List {
        /// Environment (default: all).
        #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
        env: Option<String>,
    },
}

/// History filters shared by list and search.
#[derive(Debug, Clone, Args, Default)]
pub struct HistoryFilter {
    /// Status code (404) or class (4xx).
    #[arg(long)]
    pub status: Option<String>,
    /// HTTP method.
    #[arg(long)]
    pub method: Option<String>,
    /// Substring of the request file path.
    #[arg(long)]
    pub file: Option<String>,
    /// Environment name.
    #[arg(short, long, add = ArgValueCandidates::new(completion::environments))]
    pub env: Option<String>,
    /// Only entries newer than this (30m, 2h, 7d, or RFC 3339).
    #[arg(long)]
    pub since: Option<String>,
    /// Maximum entries.
    #[arg(short = 'n', long, default_value_t = 20)]
    pub limit: usize,
    /// Output JSON.
    #[arg(long)]
    pub json: bool,
}

/// `curly history` subcommands.
#[derive(Debug, Subcommand)]
pub enum HistoryCommand {
    /// List recent requests.
    List {
        #[command(flatten)]
        filter: HistoryFilter,
    },
    /// Search URL, file, and response body text.
    Search {
        /// Text to look for.
        text: String,
        #[command(flatten)]
        filter: HistoryFilter,
    },
    /// Show one entry.
    Show {
        /// Entry id (`last` for the newest).
        #[arg(add = ArgValueCandidates::new(completion::history_ids))]
        id: String,
        #[command(flatten)]
        view: ViewArgs,
        /// Output JSON.
        #[arg(long)]
        json: bool,
    },
    /// Diff the responses of two entries.
    Diff {
        /// First entry id.
        #[arg(add = ArgValueCandidates::new(completion::history_ids))]
        a: String,
        /// Second entry id.
        #[arg(add = ArgValueCandidates::new(completion::history_ids))]
        b: String,
        /// Header to ignore (repeatable; `date` is ignored by default).
        #[arg(long = "ignore-header")]
        ignore: Vec<String>,
        /// Compare every header, including `date`.
        #[arg(long)]
        all_headers: bool,
        /// Plain text: no colors.
        #[arg(long)]
        plain: bool,
    },
    /// Run an entry's request file again with the same environment and variables.
    Rerun {
        /// Entry id (`last` for the newest).
        #[arg(add = ArgValueCandidates::new(completion::history_ids))]
        id: String,
        /// Add or override variables (needed for secret --var values).
        #[arg(long = "var", value_name = "NAME=VALUE", add = ArgValueCompleter::new(completion::variables))]
        vars: Vec<String>,
        #[command(flatten)]
        view: ViewArgs,
        /// Show secrets in output.
        #[arg(long)]
        show_secrets: bool,
    },
    /// Save an entry's (redacted) response as the request's example for `curly mock`.
    Save {
        /// Entry id (`last` for the newest).
        #[arg(add = ArgValueCandidates::new(completion::history_ids))]
        id: String,
        /// Overwrite an existing example.
        #[arg(long)]
        force: bool,
    },
    /// Delete old entries.
    Prune {
        /// Keep only the newest N entries.
        #[arg(long)]
        keep: Option<usize>,
        /// Delete entries older than this (30m, 2h, 7d).
        #[arg(long)]
        older_than: Option<String>,
        /// Delete everything.
        #[arg(long)]
        all: bool,
    },
}

/// Whether stdout should get ANSI colors.
pub fn use_color(plain: bool) -> bool {
    !plain && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

/// Parses `30m`/`2h`/`7d`/`45s` as a time that long ago, or an RFC 3339 timestamp.
pub fn parse_since(s: &str) -> Result<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num
        .parse()
        .with_context(|| format!("invalid duration `{s}` (use 30m, 2h, 7d)"))?;
    let d = match unit {
        "s" => Duration::seconds(n),
        "m" => Duration::minutes(n),
        "h" => Duration::hours(n),
        "d" => Duration::days(n),
        "w" => Duration::weeks(n),
        _ => bail!("invalid duration unit in `{s}` (use s, m, h, d, w)"),
    };
    Ok(Utc::now() - d)
}

fn write_out(bytes: &[u8]) -> Result<()> {
    let mut out = std::io::stdout().lock();
    match out.write_all(bytes).and_then(|_| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        r => Ok(r?),
    }
}

/// The curl command words from `--`-arguments or stdin.
fn command_words(command: &[String], from_stdin: bool) -> Result<Vec<String>> {
    if from_stdin || command.is_empty() {
        if !from_stdin && std::io::stdin().is_terminal() {
            bail!(
                "pass the curl command after `--` (e.g. `curly new x.curl -- curl https://...`) or pipe it with --stdin"
            );
        }
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        return crate::curlcmd::split_command(&text);
    }
    if command.len() == 1 && command[0].contains(char::is_whitespace) {
        return crate::curlcmd::split_command(&command[0]);
    }
    Ok(command.to_vec())
}

/// Outcome of [`save_command`].
struct Saved {
    rel: PathBuf,
    text: String,
    dropped: Vec<String>,
    env_added: Vec<String>,
    stored: Vec<String>,
    unstored: Vec<String>,
}

/// Converts `words` into a request file at `path` and records new variables.
#[allow(clippy::too_many_arguments)]
fn save_command(
    project: &Project,
    cli_dir: &Option<PathBuf>,
    path: &Path,
    words: &[String],
    name: Option<String>,
    literal: bool,
    store_secrets: bool,
    env: Option<&str>,
    force: bool,
) -> Result<Saved> {
    let abs = match cli_dir {
        Some(d) if path.is_relative() => d.join(path),
        _ => path.to_path_buf(),
    };
    let abs = if abs.extension().is_some_and(|e| e == "curl") {
        abs
    } else {
        PathBuf::from(format!("{}.curl", abs.display()))
    };
    std::fs::create_dir_all(abs.parent().unwrap_or(Path::new(".")))?;
    let rel = project
        .relative(abs.parent().unwrap_or(Path::new(".")))?
        .join(abs.file_name().unwrap_or_default());
    if project.root.join(&rel).exists() && !force {
        bail!("{} exists (use --force to overwrite)", rel.display());
    }
    let env_name = env
        .map(str::to_string)
        .or(project.config.project.default_env.clone())
        .unwrap_or_else(|| "local".into());
    let layers = Layers {
        folder: folder::folder_vars(project, &rel)?,
        ..Default::default()
    };
    let has_env = crate::vars::list_environments(project)?
        .iter()
        .any(|e| e.name == env_name);
    let values = crate::vars::VarContext::build(
        project,
        has_env.then_some(env_name.as_str()),
        &layers,
        None,
    )?
    .values(&project.root);
    let catalog = OptionCatalog::load(&project.curl_path())?;
    let names = SecretNames::new(&project.config.redact.variables)?;
    let opts = crate::curlcmd::ConvertOptions {
        template: !literal,
        base_url: values.get("BASE_URL").cloned(),
        name: name.or_else(|| rel.file_stem().map(|s| s.to_string_lossy().into_owned())),
    };
    let converted = crate::curlcmd::convert(words, &catalog, &opts, &names)?;
    std::fs::write(project.root.join(&rel), &converted.text)?;
    let specs: Vec<crate::vars::EnvVarSpec> = converted
        .vars
        .iter()
        .map(|v| crate::vars::EnvVarSpec {
            name: v.name.clone(),
            value: (!v.secret).then(|| v.value.clone()),
            comment: Some(format!("from `curly new {}`", rel.display())),
        })
        .collect();
    let (_, env_added) = crate::vars::add_env_variables(
        &project.root,
        &env_name,
        &specs,
        &format!("Added by `curly new` for {}", rel.display()),
    )?;
    let (mut stored, mut unstored) = (Vec::new(), Vec::new());
    let secrets: Vec<&crate::curlcmd::NewVar> =
        converted.vars.iter().filter(|v| v.secret).collect();
    if !secrets.is_empty() {
        if store_secrets {
            let store = open_store(project)?;
            let mut index = SecretIndex::load(project)?;
            for v in secrets {
                store.set(&env_name, &v.name, &v.value)?;
                index.update(&env_name, &v.name, true)?;
                stored.push(v.name.clone());
            }
        } else {
            unstored = secrets.iter().map(|v| v.name.clone()).collect();
        }
    }
    Ok(Saved {
        rel,
        text: converted.text,
        dropped: converted.dropped,
        env_added,
        stored,
        unstored,
    })
}

/// Prints what [`save_command`] did.
fn report_saved(project: &Project, s: &Saved, env: Option<&str>) -> Result<()> {
    let p = Paint {
        on: use_color(false),
    };
    eprintln!("{} {}", p.green("created"), s.rel.display());
    eprint!(
        "{}",
        s.text
            .lines()
            .map(|l| format!("  {l}\n"))
            .collect::<String>()
    );
    if !s.dropped.is_empty() {
        eprintln!(
            "{}",
            p.dim(&format!(
                "  dropped output-only options (curly sets output per run): {}",
                s.dropped.join(" ")
            ))
        );
    }
    let env_name = env
        .map(str::to_string)
        .or(project.config.project.default_env.clone())
        .unwrap_or_else(|| "local".into());
    if !s.env_added.is_empty() {
        eprintln!("  envs/{env_name}.curl: added {}", s.env_added.join(", "));
    }
    if !s.stored.is_empty() {
        eprintln!(
            "  {} {} (in {}; never written to files)",
            p.yellow("stored secrets:"),
            s.stored.join(", "),
            open_store(project)?.backend()
        );
    }
    if !s.unstored.is_empty() {
        eprintln!(
            "  {} {} (curly secret set NAME -e {env_name}, or export them)",
            p.yellow("secrets to provide:"),
            s.unstored.join(", ")
        );
    }
    Ok(())
}

/// Moves curly's own flags out of `curly curl` arguments, wherever they appear.
/// Only flags curl does not have are taken (plus `-v`/`--verbose`, which mean
/// curly's verbose view; curl's own verbose output is not shown anyway).
fn take_curly_flags(args: &CurlArgs) -> Result<(CurlArgs, Vec<String>)> {
    let mut out = CurlArgs {
        view: args.view.clone(),
        save: args.save.clone(),
        env: args.env.clone(),
        no_history: args.no_history,
        show_secrets: args.show_secrets,
        args: vec![],
    };
    let mut words = Vec::new();
    let mut it = command_words(&args.args, false)?.into_iter();
    while let Some(w) = it.next() {
        let mut value = |flag: &str| it.next().with_context(|| format!("{flag} needs a value"));
        match w.as_str() {
            "-v" | "--verbose" => out.view.verbose = true,
            "--plain" => out.view.plain = true,
            "--body" => out.view.body = true,
            "--headers" => out.view.headers = true,
            "--tui" => out.view.tui = true,
            "--show-secrets" => out.show_secrets = true,
            "--no-history" => out.no_history = true,
            "--jq" => out.view.jq = Some(value("--jq")?),
            "--path" => out.view.path = Some(value("--path")?),
            "--save" => out.save = Some(PathBuf::from(value("--save")?)),
            "--env" => out.env = Some(value("--env")?),
            _ => words.push(w),
        }
    }
    Ok((out, words))
}

/// Runs curl arguments as-is (`curly curl`), inside a collection or not.
fn cmd_curl(cli_dir: &Option<PathBuf>, args: &CurlArgs) -> Result<i32> {
    let project = project_at(cli_dir).ok();
    let (args, words) = take_curly_flags(args)?;
    let args = &args;
    if let Some(save) = &args.save {
        let project = project.context("--save needs a collection (run `curly init` first)")?;
        let saved = save_command(
            &project,
            cli_dir,
            save,
            &words,
            None,
            false,
            true,
            args.env.as_deref(),
            false,
        )?;
        report_saved(&project, &saved, args.env.as_deref())?;
        let run = RunArgs {
            paths: vec![project.root.join(&saved.rel)],
            vars: VarArgs {
                env: args.env.clone(),
                vars: vec![],
            },
            view: args.view.clone(),
            data: None,
            bail: false,
            reports: vec![],
            responses: false,
            no_history: args.no_history,
            show_secrets: args.show_secrets,
        };
        return cmd_run(cli_dir, &run);
    }
    let curl_path = project
        .as_ref()
        .map(|p| p.curl_path())
        .unwrap_or_else(|| "curl".into());
    let curl = Curl::detect(&curl_path)?;
    let catalog = OptionCatalog::load(&curl_path)?;
    let (config, dropped) = crate::curlcmd::literal_config(&words, &catalog)?;
    if !dropped.is_empty() {
        eprintln!(
            "{}",
            Paint {
                on: use_color(false)
            }
            .dim(&format!(
                "ignoring output-only options (curly shows the response): {}",
                dropped.join(" ")
            ))
        );
    }
    let view = args.view.options();
    if args.view.tui {
        crate::tui::require_terminal()?;
    }
    let (root, layers, child_env, secrets, redact_cfg) = match &project {
        Some(p) => {
            let ctx = if crate::curlconf::var_refs(&config).is_empty() {
                crate::vars::VarContext::build(p, args.env.as_deref(), &Layers::default(), None)?
            } else {
                var_context(p, None, args.env.as_deref(), Layers::default())?
            };
            (
                p.root.clone(),
                ctx.layers(),
                ctx.child_env.clone(),
                ctx.secret_values(&p.root),
                p.config.redact.clone(),
            )
        }
        None => (
            std::env::current_dir()?,
            vec![],
            vec![],
            vec![],
            crate::project::RedactSection::default(),
        ),
    };
    let inv = crate::curlexec::Invocation {
        root,
        layers,
        request: crate::vars::ConfigLayer::Text(config.clone()),
        child_env,
    };
    let raw = inv.execute(&curl)?;
    let redactor = crate::redact::Redactor::new(&redact_cfg, secrets)?;
    let redacted = redactor.exchange(&raw);
    let mut history_id = None;
    if let Some(p) = &project
        && !args.no_history
        && p.config.history.enabled
    {
        let meta = crate::history::NewEntry {
            file: None,
            env: args.env.clone().or(p.config.project.default_env.clone()),
            vars: Default::default(),
            file_sha256: None,
            redacted: redact_cfg.enabled,
        };
        history_id = Some(open_history(p)?.insert(
            &meta,
            if redact_cfg.enabled { &redacted } else { &raw },
            p.config.history.max_body_bytes,
        )?);
    }
    let shown = if args.show_secrets || !redact_cfg.enabled {
        raw
    } else {
        redacted
    };
    if args.view.tui {
        crate::tui::view_exchange(shown.request.url.clone(), shown)?;
        return Ok(EXIT_OK);
    }
    let rendered = render(&shown, &view)?;
    if shown.response.is_none() {
        eprint!("{}", String::from_utf8_lossy(&rendered));
        return Ok(EXIT_TRANSPORT);
    }
    write_out(&rendered)?;
    if let (Some(id), true) = (history_id, view.mode == Mode::Full && view.filter.is_none()) {
        eprintln!(
            "{}",
            Paint { on: view.color }.dim(&format!(
                "history #{id}  (save it as a request file: curly curl --save FILE ...)"
            ))
        );
    }
    Ok(EXIT_OK)
}

/// Rewrites request and environment files in command-line style.
fn cmd_fmt(cli_dir: &Option<PathBuf>, paths: &[PathBuf], check: bool) -> Result<i32> {
    let project = project_at(cli_dir)?;
    let mut files: Vec<PathBuf> = Vec::new();
    if paths.is_empty() {
        files.extend(find_requests(&project.root, &project.root)?);
        if let Ok(entries) = std::fs::read_dir(project.envs_dir()) {
            files.extend(
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "curl")),
            );
        }
    } else {
        for p in paths {
            let abs = cli_dir
                .as_ref()
                .filter(|_| p.is_relative())
                .map(|d| d.join(p))
                .unwrap_or(p.clone());
            if abs.is_dir() {
                files.extend(find_requests(&project.root, &std::fs::canonicalize(&abs)?)?);
            } else {
                files.push(abs);
            }
        }
    }
    files.sort();
    files.dedup();
    let mut changed = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f)?;
        let formatted = crate::curlconf::format_flags(&text);
        if formatted != text {
            if !check {
                std::fs::write(f, &formatted)?;
            }
            changed.push(project.relative(f).unwrap_or(f.clone()));
        }
    }
    for c in &changed {
        println!(
            "{}{}",
            if check {
                "would reformat "
            } else {
                "formatted "
            },
            c.display()
        );
    }
    println!(
        "{} of {} files {}",
        changed.len(),
        files.len(),
        if check {
            "need formatting"
        } else {
            "reformatted"
        }
    );
    Ok(if check && !changed.is_empty() {
        EXIT_FAILED
    } else {
        EXIT_OK
    })
}

/// Re-runs history entry `e` with its environment and `--var`s (plus `overrides`).
fn rerun_entry(
    project: &Project,
    e: &Entry,
    overrides: &[(String, String)],
    show_secrets: bool,
) -> Result<crate::request::RunResult> {
    let file = e
        .file
        .clone()
        .context("entry has no request file to re-run")?;
    let rel = PathBuf::from(&file);
    let source = std::fs::read(project.absolute(&rel)?)
        .with_context(|| format!("request file {file} no longer exists"))?;
    if e.file_sha256
        .as_deref()
        .is_some_and(|s| s != crate::request::sha256_hex(&source))
    {
        eprintln!(
            "note: {file} changed since #{}; running the current version",
            e.id
        );
    }
    let mut merged: Vec<(String, String)> = Vec::new();
    for (k, v) in &e.vars {
        if let Some((_, o)) = overrides.iter().find(|(ok, _)| ok == k) {
            merged.push((k.clone(), o.clone()));
        } else if let Some(v) = v {
            merged.push((k.clone(), v.clone()));
        } else {
            bail!(
                "#{} used a secret --var {k}; pass it again with --var {k}=...",
                e.id
            );
        }
    }
    merged.extend(
        overrides
            .iter()
            .filter(|(k, _)| !e.vars.contains_key(k))
            .cloned(),
    );
    let curl = Curl::detect(&project.curl_path())?;
    let opts = RunOptions {
        env: e.env.clone(),
        vars: merged,
        record: true,
        show_secrets,
        ..Default::default()
    };
    crate::request::run_any(project, &curl, &rel, &opts)
}

/// Parses an entry id or `last`.
fn entry_id(h: &crate::history::History, id: &str) -> Result<i64> {
    if id == "last" {
        return h
            .search(&Query {
                limit: 1,
                ..Default::default()
            })?
            .first()
            .map(|e| e.id)
            .context("history is empty");
    }
    id.trim_start_matches('#')
        .parse()
        .with_context(|| format!("invalid history id `{id}`"))
}

fn project_at(dir: &Option<PathBuf>) -> Result<Project> {
    Project::discover(dir.as_deref().unwrap_or(Path::new(".")))
}

/// Resolves a user-supplied path against `-C` and returns it relative to the root.
fn request_rel(project: &Project, dir: &Option<PathBuf>, file: &Path) -> Result<PathBuf> {
    let p = match dir {
        Some(d) if file.is_relative() => d.join(file),
        _ => file.to_path_buf(),
    };
    project.relative(&p)
}

/// Prints a single request's response and its checks.
fn print_single(r: &StepResult, view: &ViewOptions) -> Result<()> {
    let p = Paint { on: view.color };
    if let Some(ex) = &r.exchange {
        let rendered = render(ex, view)?;
        if ex.response.is_some() {
            write_out(&rendered)?;
        } else {
            eprint!("{}", String::from_utf8_lossy(&rendered));
        }
    }
    if r.exchange.as_ref().is_none_or(|e| e.response.is_some())
        && r.error_kind != Some(runner::ErrorKind::Config)
        && let Some(e) = &r.error
    {
        eprintln!("error: {e}");
    }
    if !r.assertions.is_empty() {
        let passed = r.assertions.iter().filter(|a| a.passed).count();
        eprint!("\n{}", report::assertion_lines(&r.assertions, p, false));
        let total = r.assertions.len();
        let line = if passed == total {
            p.green(&format!("all {total} checks passed"))
        } else {
            p.red(&format!("{passed} of {total} checks passed"))
        };
        eprintln!("    {line}");
    }
    if let (Some(id), true) = (
        r.history_id,
        view.mode == Mode::Full && view.filter.is_none(),
    ) {
        eprintln!("{}", p.dim(&format!("history #{id}")));
    }
    Ok(())
}

fn cmd_run(cli_dir: &Option<PathBuf>, args: &RunArgs) -> Result<i32> {
    let project = project_at(cli_dir)?;
    let curl = Curl::detect(&project.curl_path())?;
    let reports = args
        .reports
        .iter()
        .map(|s| report::parse_spec(s))
        .collect::<Result<Vec<_>>>()?;
    let targets = args
        .paths
        .iter()
        .map(|p| request_rel(&project, cli_dir, p))
        .collect::<Result<Vec<_>>>()?;
    let steps = runner::plan(&project, &targets)?;
    let data = match &args.data {
        Some(d) => Some(
            cli_dir
                .as_ref()
                .filter(|_| d.is_relative())
                .map(|c| c.join(d))
                .unwrap_or(d.clone()),
        ),
        None => runner::folder_data(&project, &targets)?,
    };
    let rows = data
        .as_deref()
        .map(runner::load_data)
        .transpose()?
        .unwrap_or_default();
    let opts = RunnerOptions {
        env: args.vars.env.clone(),
        vars: parse_cli_vars(&args.vars.vars)?,
        bail: args.bail,
        record: !args.no_history,
        show_secrets: args.show_secrets,
    };
    let view = args.view.options();
    let p = Paint { on: view.color };
    let single = steps.len() == 1 && rows.len() <= 1;
    if args.view.tui {
        crate::tui::require_terminal()?;
    }
    let mut tui_view: Option<(String, crate::curlexec::Exchange)> = None;
    let mut printed_err = None;
    let report = runner::run(&project, &curl, &steps, &rows, &opts, &mut |r| {
        let res = if single && args.view.tui && r.exchange.is_some() {
            tui_view = r.exchange.clone().map(|ex| (r.file.clone(), ex));
            Ok(())
        } else if single {
            print_single(r, &view)
        } else {
            let mut out = report::step_line(r, p, rows.len() > 1, view.verbose);
            if args.responses
                && let Some(ex) = &r.exchange
            {
                out.push_str(&String::from_utf8_lossy(
                    &render(ex, &view).unwrap_or_default(),
                ));
                out.push('\n');
            }
            write_out(out.as_bytes())
        };
        if let Err(e) = res {
            printed_err.get_or_insert(e);
        }
    });
    if let Some(e) = printed_err {
        return Err(e);
    }
    if single {
        if let (Some(kind), Some(e)) = (report.results[0].error_kind, &report.results[0].error)
            && kind == runner::ErrorKind::Config
        {
            bail!("{e}");
        }
    } else {
        write_out(format!("\n{}", report::summary_line(&report, p)).as_bytes())?;
    }
    for (format, path) in &reports {
        let path = cli_dir
            .as_ref()
            .filter(|_| path.is_relative())
            .map(|c| c.join(path))
            .unwrap_or(path.clone());
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, report::render(&report, *format)?)
            .with_context(|| format!("writing {}", path.display()))?;
        eprintln!("{}", p.dim(&format!("wrote {}", path.display())));
    }
    if args.view.tui {
        match tui_view {
            Some((title, ex)) => crate::tui::view_exchange(title, ex)?,
            None if !single => {
                let h = open_history(&project)?;
                let load = || {
                    h.search(&Query {
                        limit: 500,
                        ..Default::default()
                    })
                };
                let mut rerun = |id: i64| -> Result<String> {
                    let r = rerun_entry(&project, &h.get(id)?, &[], args.show_secrets)?;
                    Ok(format!(
                        "re-ran #{id} as #{}",
                        r.history_id.unwrap_or_default()
                    ))
                };
                crate::tui::browse_history(load()?, &mut rerun, &mut || load())?;
            }
            None => {}
        }
    }
    Ok(report.exit_code())
}

/// Variable names any request may rely on besides the environment: captures
/// declared in sidecars and columns of folder data files.
fn collection_provided_names(project: &Project, files: &[PathBuf]) -> Vec<String> {
    let mut names = Vec::new();
    for f in files {
        if let Ok(Some(t)) = TestFile::load_for(&project.root, f) {
            names.extend(t.capture_names());
        }
        if let Ok(chain) = folder::chain(project, f) {
            for (_, cfg) in chain {
                if let Some(rows) = cfg
                    .data
                    .and_then(|d| runner::load_data(&project.root.join(d)).ok())
                {
                    names.extend(rows[0].iter().map(|(k, _)| k.clone()));
                }
            }
        }
    }
    names
}

/// Lints `_folder.toml` files and sidecars that belong to `files`.
fn lint_support_files(
    project: &Project,
    files: &[PathBuf],
    names: &SecretNames,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let diag = |file: PathBuf, level: Level, message: String| Diagnostic {
        file,
        line: 0,
        level,
        message,
    };
    let mut folders = BTreeSet::new();
    for f in files {
        let side = assertions::sidecar_path(f);
        if let Err(e) = TestFile::load_for(&project.root, f) {
            out.push(diag(
                side,
                Level::Error,
                format!("{:#}", e).replace(
                    &format!("parsing {}: ", assertions::sidecar_path(f).display()),
                    "",
                ),
            ));
        }
        let mut dir = f.parent().map(Path::to_path_buf).unwrap_or_default();
        loop {
            folders.insert(dir.clone());
            if !dir.pop() {
                break;
            }
        }
    }
    for dir in folders {
        let file = dir.join(folder::FOLDER_FILE);
        match folder::load(&project.root.join(&dir)) {
            Err(e) => out.push(diag(file, Level::Error, format!("{:#}", e.root_cause()))),
            Ok(None) => {}
            Ok(Some(cfg)) => {
                if let Err(e) = folder::expand(project, &dir) {
                    out.push(diag(file.clone(), Level::Error, format!("{e:#}")));
                }
                for problem in cfg.auth.iter().flat_map(|a| a.problems()) {
                    out.push(diag(file.clone(), Level::Error, problem));
                }
                for name in cfg.vars.keys().filter(|n| names.is_secret(n)) {
                    out.push(diag(file.clone(), Level::Error, format!("hardcoded credential `{name}` in [vars]; use an environment secret instead")));
                }
                if let Some(d) = &cfg.data
                    && let Err(e) = runner::load_data(&project.root.join(d))
                {
                    out.push(diag(file.clone(), Level::Error, format!("{e:#}")));
                }
            }
        }
    }
    out
}

fn cmd_lint(cli_dir: &Option<PathBuf>, paths: &[PathBuf], vars: &VarArgs) -> Result<i32> {
    let project = project_at(cli_dir)?;
    let catalog = OptionCatalog::load(&project.curl_path()).ok();
    let cli_vars = parse_cli_vars(&vars.vars)?;
    let mut files = Vec::new();
    let roots: Vec<PathBuf> = if paths.is_empty() {
        vec![project.root.clone()]
    } else {
        paths
            .iter()
            .map(|p| cli_dir.as_ref().map(|d| d.join(p)).unwrap_or(p.clone()))
            .collect()
    };
    for r in roots {
        if r.is_dir() {
            files.extend(find_requests(&project.root, &std::fs::canonicalize(&r)?)?);
        } else {
            files.push(r);
        }
    }
    let p = Paint {
        on: use_color(false),
    };
    let rels = files
        .iter()
        .map(|f| project.relative(f))
        .collect::<Result<Vec<_>>>()?;
    let provided = collection_provided_names(&project, &rels);
    let mut diagnostics = lint_support_files(
        &project,
        &rels,
        &SecretNames::new(&project.config.redact.variables)?,
    );
    let index = SecretIndex::load(&project)?;
    for rel in &rels {
        // Lint needs only which secrets exist, so it never reads the keychain
        // (each read can prompt for the login password).
        let layers = Layers {
            folder: folder::folder_vars(&project, rel)?,
            cli: cli_vars.clone(),
            ..Default::default()
        };
        let ctx = crate::vars::VarContext::build(&project, vars.env.as_deref(), &layers, None)?;
        let stored = ctx
            .env
            .as_ref()
            .map(|e| index.names(&e.name))
            .unwrap_or_default();
        let auth = crate::oauth::find(&project, rel).ok().flatten();
        let lint_ctx = LintContext {
            catalog: catalog.as_ref(),
            defined: ctx
                .defined_names()
                .into_iter()
                .chain(stored)
                .chain(provided.iter().cloned())
                .chain(auth.iter().map(|(_, a)| a.token_var.clone()))
                .collect::<BTreeSet<_>>(),
            env_name: ctx.env.as_ref().map(|e| e.name.clone()),
        };
        let spec = RequestSpec::load(&project.root, rel)?;
        if let Some((folder, a)) = &auth
            && !spec.var_refs.iter().any(|(_, v)| *v == a.token_var)
        {
            diagnostics.push(Diagnostic {
                file: rel.clone(),
                line: 0,
                level: Level::Warning,
                message: format!(
                    "{} sets [auth], but this request never uses {{{{{}}}}}; add expand-header = \"Authorization: Bearer {{{{{}}}}}\"",
                    folder.join(folder::FOLDER_FILE).display(),
                    a.token_var,
                    a.token_var
                ),
            });
        }
        if let Ok(Some(check)) =
            crate::graphql::check_request(&project, &spec, &ctx.values(&project.root))
        {
            diagnostics.extend(check.diagnostics.into_iter().map(|d| Diagnostic {
                file: check.document.clone(),
                line: d.line,
                level: Level::Error,
                message: d.message,
            }));
        }
        if crate::request::is_ws(rel) || crate::request::is_grpc(rel) {
            let unsupported = if crate::request::is_ws(rel) {
                crate::ws::unsupported_options(&spec)
            } else {
                crate::grpc::unsupported_options(&spec)
            };
            diagnostics.extend(unsupported.into_iter().map(|(line, message)| Diagnostic {
                file: rel.clone(),
                line,
                level: Level::Error,
                message,
            }));
            let ws_ctx = LintContext {
                catalog: None,
                ..lint_ctx
            };
            diagnostics.extend(lint_request(&spec, &ws_ctx));
            continue;
        }
        diagnostics.extend(lint_request(&spec, &lint_ctx));
    }
    let (mut errors, mut warnings) = (0, 0);
    {
        for d in diagnostics {
            match d.level {
                Level::Error => errors += 1,
                Level::Warning => warnings += 1,
            }
            let line = d.to_string();
            println!(
                "{}",
                if d.level == Level::Error {
                    p.red(&line)
                } else {
                    p.yellow(&line)
                }
            );
        }
    }
    println!(
        "{} files checked, {errors} errors, {warnings} warnings",
        files.len()
    );
    Ok(if errors > 0 { EXIT_FAILED } else { EXIT_OK })
}

fn cmd_import(cli_dir: &Option<PathBuf>, cmd: &ImportCommand) -> Result<i32> {
    let ImportCommand::Openapi {
        source,
        out,
        env,
        force,
    } = cmd;
    let cwd = match cli_dir {
        Some(d) => d.clone(),
        None => std::env::current_dir()?,
    };
    let curl = Project::discover(&cwd)
        .map(|p| p.curl_path())
        .unwrap_or_else(|_| "curl".into());
    let opts = crate::openapi::ImportOptions {
        source: source.clone(),
        out: out.clone(),
        env: env.clone(),
        force: *force,
        curl,
        cwd,
    };
    let s = crate::openapi::import(&opts)?;
    let p = Paint {
        on: use_color(false),
    };
    let out_display = if s.out.as_os_str().is_empty() {
        ".".to_string()
    } else {
        format!("{}/", s.out.display())
    };
    println!(
        "{} {} operations from {} into {out_display}",
        p.green("Imported"),
        s.operations,
        s.title
    );
    if s.new_collection {
        println!("  created a new collection at {}", s.root.display());
    }
    println!(
        "  {} files written, {} existing files kept{}",
        s.created.len(),
        s.skipped.len(),
        if s.skipped.is_empty() {
            ""
        } else {
            " (use --force to overwrite)"
        }
    );
    if !s.env_added.is_empty() {
        println!(
            "  {}: added {}",
            s.env_file.display(),
            s.env_added.join(", ")
        );
    }
    if !s.secrets.is_empty() {
        println!(
            "  {} {}",
            p.yellow("secrets to provide:"),
            s.secrets.join(", ")
        );
        println!("    curly secret set NAME -e {env}   (or export NAME in your shell)");
    }
    for w in &s.warnings {
        println!("  {} {w}", p.yellow("note:"));
    }
    println!("Next: curly lint {out_display} && curly run {out_display}");
    Ok(EXIT_OK)
}

/// Resolves the `[auth]` that applies to `path` in `env`.
fn resolve_auth(
    project: &Project,
    cli_dir: &Option<PathBuf>,
    path: &Option<PathBuf>,
    env: &Option<String>,
) -> Result<crate::oauth::ResolvedAuth> {
    let rel = match path {
        Some(p) => request_rel(project, cli_dir, p)?,
        None => PathBuf::new(),
    };
    let anchor = crate::oauth::chain_anchor(project, &rel);
    let ctx = var_context(project, Some(&anchor), env.as_deref(), Layers::default())?;
    crate::oauth::resolve(project, &rel, &ctx)?.with_context(|| {
        format!(
            "no [auth] applies to {}",
            if rel.as_os_str().is_empty() {
                ".".into()
            } else {
                rel.display().to_string()
            }
        )
    })
}

fn cmd_auth(cli_dir: &Option<PathBuf>, cmd: &AuthCommand) -> Result<i32> {
    let project = project_at(cli_dir)?;
    let p = Paint {
        on: use_color(false),
    };
    match cmd {
        AuthCommand::Login {
            path,
            env,
            no_browser,
            timeout,
        } => {
            let auth = resolve_auth(&project, cli_dir, path, env)?;
            let curl = Curl::detect(&project.curl_path())?;
            let opts = crate::oauth::LoginOptions {
                open_browser: !no_browser,
                timeout: std::time::Duration::from_secs(*timeout),
            };
            let tokens = crate::oauth::login(&project, &curl, &auth, &opts)?;
            let expiry = tokens
                .expires_at
                .map(|t| format!("expires in {}", human_duration(t - Utc::now().timestamp())))
                .unwrap_or_else(|| "no expiry".into());
            let refresh = if tokens.refresh_token.is_some() {
                ", refreshable"
            } else {
                ""
            };
            eprintln!(
                "{} {} ({}, {expiry}{refresh}); cached in {}",
                p.green("Logged in:"),
                auth.folder_display(),
                auth.flow().as_str(),
                open_store(&project)?.backend()
            );
        }
        AuthCommand::Token { path, env } => {
            let auth = resolve_auth(&project, cli_dir, path, env)?;
            let curl = Curl::detect(&project.curl_path())?;
            println!(
                "{}",
                crate::oauth::access_token(&project, &curl, &auth, crate::oauth::interactive())?
            );
        }
        AuthCommand::Status => {
            let now = Utc::now().timestamp();
            let index = crate::oauth::cache_index(&project)?;
            if index.is_empty() {
                println!("no cached tokens");
            }
            for meta in index.values() {
                let expiry = match meta.expires_at {
                    Some(t) if t > now => {
                        p.green(&format!("expires in {}", human_duration(t - now)))
                    }
                    Some(_) => p.yellow("expired"),
                    None => "no expiry".into(),
                };
                let refresh = if meta.refreshable {
                    "refreshable"
                } else {
                    "not refreshable"
                };
                let scopes = if meta.scopes.is_empty() {
                    "-".into()
                } else {
                    meta.scopes.join(" ")
                };
                println!(
                    "{}  env={}  {}  client={}  scopes={scopes}  {expiry}, {refresh}",
                    meta.folder, meta.env, meta.flow, meta.client_id
                );
            }
        }
        AuthCommand::Logout { path, env, all } => {
            let n = if *all {
                crate::oauth::logout(&project, &|_| true)?
            } else {
                let auth = resolve_auth(&project, cli_dir, path, env)?;
                let (folder, env) = (auth.folder_display(), auth.env.clone());
                crate::oauth::logout(&project, &|m| m.folder == folder && m.env == env)?
            };
            println!("removed {n} cached token{}", if n == 1 { "" } else { "s" });
        }
    }
    Ok(EXIT_OK)
}

/// Cached schema for the GraphQL request `rel`, or an error saying how to get one.
fn schema_for(
    project: &Project,
    rel: &Path,
    env: Option<&str>,
) -> Result<(String, crate::graphql::CachedSchema)> {
    let endpoint = crate::graphql::request_endpoint(project, rel, env)?;
    let cached = crate::graphql::load_schema(project, &endpoint)?.with_context(|| {
        format!(
            "no cached schema for {endpoint}; run `curly gql introspect {}`",
            rel.display()
        )
    })?;
    Ok((endpoint, cached))
}

fn cmd_gql(cli_dir: &Option<PathBuf>, cmd: &GqlCommand) -> Result<i32> {
    use crate::graphql;
    let project = project_at(cli_dir)?;
    let p = Paint {
        on: use_color(false),
    };
    match cmd {
        GqlCommand::Introspect { request, vars } => {
            let rel = request_rel(&project, cli_dir, request)?;
            let spec = RequestSpec::load(&project.root, &rel)?;
            if graphql::graphql_files(&spec).is_none() {
                bail!(
                    "{} is not a GraphQL request (it must read a .graphql file with `variable = \"NAME@file.graphql\"`)",
                    rel.display()
                );
            }
            let curl = Curl::detect(&project.curl_path())?;
            let opts = RunOptions {
                env: vars.env.clone(),
                vars: parse_cli_vars(&vars.vars)?,
                record: true,
                body_override: Some(graphql::introspection_body()),
                ..Default::default()
            };
            let r = run_request(&project, &curl, &rel, &opts)?;
            let resp = r.exchange.response.as_ref().with_context(|| {
                format!(
                    "introspection failed: {}",
                    r.exchange.error.clone().unwrap_or_default()
                )
            })?;
            if !(200..300).contains(&resp.status) {
                bail!(
                    "introspection returned HTTP {}: {}",
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                        .chars()
                        .take(300)
                        .collect::<String>()
                );
            }
            let body: serde_json::Value =
                serde_json::from_slice(&resp.body).context("introspection response is not JSON")?;
            let endpoint = graphql::endpoint(&r.spec, &r.vars)?;
            let path = graphql::save_schema(&project, &endpoint, &body)?;
            let schema = &body["data"]["__schema"];
            let user_types = schema["types"]
                .as_array()
                .map(|t| {
                    t.iter()
                        .filter(|t| !t["name"].as_str().unwrap_or("__").starts_with("__"))
                        .count()
                })
                .unwrap_or(0);
            let roots: Vec<String> = ["queryType", "mutationType", "subscriptionType"]
                .iter()
                .filter_map(|k| schema[k]["name"].as_str())
                .map(|n| format!("{n} ({} fields)", graphql::fields_of(schema, n).len()))
                .collect();
            println!(
                "{} {endpoint}: {user_types} types; {}",
                p.green("Cached schema for"),
                roots.join(", ")
            );
            println!(
                "  {}",
                path.strip_prefix(&project.root).unwrap_or(&path).display()
            );
        }
        GqlCommand::Check { paths, env } => {
            let rels: Vec<PathBuf> = if paths.is_empty() {
                graphql::graphql_requests(&project)
                    .into_iter()
                    .map(|(r, _)| r)
                    .collect()
            } else {
                let targets = paths
                    .iter()
                    .map(|x| request_rel(&project, cli_dir, x))
                    .collect::<Result<Vec<_>>>()?;
                runner::plan(&project, &targets)?
            };
            let (mut errors, mut checked, mut skipped) = (0, 0, 0);
            for rel in &rels {
                let spec = RequestSpec::load(&project.root, rel)?;
                if graphql::graphql_files(&spec).is_none() {
                    continue;
                }
                let values = var_context(&project, Some(rel), env.as_deref(), Layers::default())?
                    .values(&project.root);
                match graphql::check_request(&project, &spec, &values)? {
                    None => {
                        skipped += 1;
                        println!(
                            "{} {}: no cached schema; run `curly gql introspect {}`",
                            p.yellow("skip"),
                            rel.display(),
                            rel.display()
                        );
                    }
                    Some(check) => {
                        checked += 1;
                        for d in &check.diagnostics {
                            errors += 1;
                            println!(
                                "{}",
                                p.red(&format!(
                                    "{}: error: {}",
                                    d.location(&check.document),
                                    d.message
                                ))
                            );
                        }
                    }
                }
            }
            println!(
                "{checked} GraphQL requests checked, {errors} errors, {skipped} without a cached schema"
            );
            return Ok(if errors > 0 { EXIT_FAILED } else { EXIT_OK });
        }
        GqlCommand::Complete {
            position,
            env,
            json,
        } => {
            let mut parts = position.rsplitn(3, ':');
            let (col, line, file) = (parts.next(), parts.next(), parts.next());
            let (Some(file), Some(line), Some(col)) = (
                file,
                line.and_then(|l| l.parse().ok()),
                col.and_then(|c| c.parse().ok()),
            ) else {
                bail!("position must be FILE:LINE:COL, e.g. graphql/get-user.graphql:3:5");
            };
            let doc_rel = request_rel(&project, cli_dir, Path::new(file))?;
            let request = graphql::graphql_requests(&project)
                .into_iter()
                .find(|(_, g)| g.document == doc_rel)
                .map(|(r, _)| r)
                .with_context(|| format!("no request reads {}", doc_rel.display()))?;
            let (_, cached) = schema_for(&project, &request, env.as_deref())?;
            let text = std::fs::read_to_string(project.root.join(&doc_rel))?;
            let fields = graphql::complete_at(&cached.schema, &text, line, col);
            if *json {
                let items: Vec<serde_json::Value> = fields.iter().map(|f| serde_json::json!({"name": f.name, "type": f.ty, "description": f.description})).collect();
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                for f in fields {
                    println!("{}\t{}\t{}", f.name, f.ty, f.description);
                }
            }
        }
        GqlCommand::New {
            path,
            field,
            url,
            headers,
            env,
            force,
        } => {
            let base_abs = match cli_dir {
                Some(d) if path.is_relative() => d.join(path),
                _ => path.clone(),
            };
            let base_str = base_abs.to_string_lossy();
            let base_abs = PathBuf::from(
                base_str
                    .strip_suffix(".curl")
                    .unwrap_or(&base_str)
                    .to_string(),
            );
            if let Some(parent) = base_abs.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let parent_rel = project.relative(base_abs.parent().unwrap_or(Path::new(".")))?;
            let stem = base_abs
                .file_name()
                .context("missing request name")?
                .to_string_lossy()
                .into_owned();
            let base = parent_rel.join(&stem);
            let with_ext = |ext: &str| PathBuf::from(format!("{}.{ext}", base.display()));
            let (request, document, variables, test) = (
                with_ext("curl"),
                with_ext("graphql"),
                with_ext("vars.json"),
                with_ext("test.toml"),
            );
            for f in [&request, &document, &variables, &test] {
                if project.root.join(f).exists() && !force {
                    bail!("{} exists (use --force to overwrite)", f.display());
                }
            }
            let generated = match field {
                Some(f) => {
                    let layers = Layers {
                        folder: folder::folder_vars(&project, &request)?,
                        ..Default::default()
                    };
                    let values =
                        crate::vars::VarContext::build(&project, env.as_deref(), &layers, None)?
                            .values(&project.root);
                    let endpoint = substitute_url(url, &values)?;
                    let cached = graphql::load_schema(&project, &endpoint)?.with_context(|| format!("no cached schema for {endpoint}; create a request without --field and run `curly gql introspect` on it first"))?;
                    graphql::generate(&cached.schema, f)?
                }
                None => graphql::Generated {
                    document: "query Ping {\n  __typename\n}\n".into(),
                    variables: serde_json::json!({}),
                },
            };
            let title = field.clone().unwrap_or_else(|| stem.clone());
            let extra: Vec<String> = headers
                .iter()
                .map(|h| format!("expand-header = {}", crate::curlconf::quote(h)))
                .collect();
            std::fs::write(
                project.root.join(&request),
                graphql::request_text(&title, url, &document, &variables, &extra),
            )?;
            std::fs::write(project.root.join(&document), &generated.document)?;
            std::fs::write(
                project.root.join(&variables),
                serde_json::to_string_pretty(&generated.variables)? + "\n",
            )?;
            let mut test_text = String::from(
                "[expect]\nstatus = 200\n\n[[expect.json]]\npath = \"$.errors\"\nexists = false\n",
            );
            if let Some(f) = field
                .as_deref()
                .and_then(|f| f.split_once('.'))
                .map(|(_, f)| f)
            {
                test_text.push_str(&format!(
                    "\n[[expect.json]]\npath = \"$.data.{f}\"\nexists = true\n"
                ));
            }
            std::fs::write(project.root.join(&test), test_text)?;
            for f in [&request, &document, &variables, &test] {
                println!("created {}", f.display());
            }
            if field.is_none() {
                println!("Next: curly gql introspect {}", request.display());
            }
        }
        GqlCommand::Schema { request, env } => {
            let rel = request_rel(&project, cli_dir, request)?;
            let (endpoint, cached) = schema_for(&project, &rel, env.as_deref())?;
            println!(
                "# {endpoint} (cached {})\n{}",
                cached.fetched_at,
                crate::graphql::to_sdl(&cached.schema)
            );
        }
    }
    Ok(EXIT_OK)
}

/// Resolves the gRPC target of a `.grpc` request (variables and OAuth applied).
fn grpc_target(
    project: &Project,
    cli_dir: &Option<PathBuf>,
    file: &Path,
    env: &Option<String>,
) -> Result<crate::grpc::Target> {
    let rel = request_rel(project, cli_dir, file)?;
    if !crate::request::is_grpc(&rel) {
        bail!("{} is not a .grpc file", rel.display());
    }
    let curl = Curl::detect(&project.curl_path())?;
    let prepared = crate::request::prepare(
        project,
        &curl,
        &rel,
        &RunOptions {
            env: env.clone(),
            ..Default::default()
        },
    )?;
    crate::grpc::target(project, &prepared.spec, &prepared.ctx.values(&project.root))
}

/// A target with just an address (for listing a bare host:port).
fn bare_grpc_target(authority: &str, tls: bool, protos: Vec<PathBuf>) -> crate::grpc::Target {
    crate::grpc::Target {
        authority: authority.to_string(),
        tls,
        service: String::new(),
        method: String::new(),
        metadata: vec![],
        messages: vec![],
        protos,
        import_paths: vec![],
        timeout: None,
        connect_timeout: std::time::Duration::from_secs(10),
        tls12: false,
        cacert: None,
    }
}

fn cmd_grpc(cli_dir: &Option<PathBuf>, cmd: &GrpcCommand) -> Result<i32> {
    let project = project_at(cli_dir)?;
    match cmd {
        GrpcCommand::List { target, tls, env } => {
            let t = if target.ends_with(".grpc") {
                grpc_target(&project, cli_dir, Path::new(target), env)?
            } else {
                bare_grpc_target(target, *tls, vec![])
            };
            for (service, methods) in crate::grpc::list(&project, &t)? {
                println!("{service}");
                for m in methods {
                    println!("  {m}");
                }
            }
        }
        GrpcCommand::Describe { request, env } => {
            let t = grpc_target(&project, cli_dir, request, env)?;
            let (text, example) = crate::grpc::describe(&project, &t)?;
            println!(
                "{text}\nexample request:\n{}",
                serde_json::to_string_pretty(&example)?
            );
        }
        GrpcCommand::New {
            path,
            method,
            target,
            proto,
            headers,
            tls,
            env,
            force,
        } => {
            let (service, name) = method
                .rsplit_once('/')
                .filter(|(s, m)| !s.is_empty() && !m.is_empty())
                .context("--method must look like package.Service/Method")?;
            let base_abs = match cli_dir {
                Some(d) if path.is_relative() => d.join(path),
                _ => path.clone(),
            };
            let base_str = base_abs.to_string_lossy().into_owned();
            let base_abs = PathBuf::from(base_str.strip_suffix(".grpc").unwrap_or(&base_str));
            std::fs::create_dir_all(base_abs.parent().unwrap_or(Path::new(".")))?;
            let parent = project.relative(base_abs.parent().unwrap_or(Path::new(".")))?;
            let stem = base_abs
                .file_name()
                .context("missing request name")?
                .to_string_lossy()
                .into_owned();
            let request = parent.join(format!("{stem}.grpc"));
            let test = parent.join(format!("{stem}.test.toml"));
            for f in [&request, &test] {
                if project.root.join(f).exists() && !force {
                    bail!("{} exists (use --force to overwrite)", f.display());
                }
            }
            let layers = Layers {
                folder: folder::folder_vars(&project, &request)?,
                ..Default::default()
            };
            let values = crate::vars::VarContext::build(&project, env.as_deref(), &layers, None)?
                .values(&project.root);
            let authority = crate::curlconf::substitute(target, &values)
                .map_err(|e| anyhow::anyhow!("--target: {e}"))?;
            let mut t = bare_grpc_target(&authority, *tls, proto.clone());
            (t.service, t.method) = (service.to_string(), name.to_string());
            let (_, example) = crate::grpc::describe(&project, &t)?;
            let scheme = if *tls { "grpcs" } else { "grpc" };
            let mut text = format!(
                "# @name {name}\n# @tags grpc\nexpand-url = {}\n",
                crate::curlconf::quote(&format!("{scheme}://{target}/{service}/{name}"))
            );
            for h in headers {
                text.push_str(&format!("expand-header = {}\n", crate::curlconf::quote(h)));
            }
            for p in proto {
                text.push_str(&format!(
                    "proto = {}\n",
                    crate::curlconf::quote(&p.display().to_string())
                ));
            }
            text.push_str(&format!(
                "data = {}\n",
                crate::curlconf::quote(&serde_json::to_string(&example)?)
            ));
            std::fs::write(
                project.root.join(&request),
                crate::curlconf::format_flags(&text),
            )?;
            std::fs::write(project.root.join(&test), "[expect]\nstatus = \"OK\"\n")?;
            println!("created {}\ncreated {}", request.display(), test.display());
        }
    }
    Ok(EXIT_OK)
}

/// Expands `{{var}}` in a URL template, ignoring curl functions such as `:url`.
fn substitute_url(
    url: &str,
    values: &std::collections::BTreeMap<String, String>,
) -> Result<String> {
    let spec = RequestSpec {
        url: Some(url.to_string()),
        ..Default::default()
    };
    crate::graphql::endpoint(&spec, values)
}

/// `90` -> `1m 30s`, `7200` -> `2h 0m`.
fn human_duration(secs: i64) -> String {
    let secs = secs.max(0);
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        s => format!("{}h {}m", s / 3600, (s % 3600) / 60),
    }
}

fn cmd_env(cli_dir: &Option<PathBuf>, cmd: &EnvCommand) -> Result<i32> {
    let project = project_at(cli_dir)?;
    match cmd {
        EnvCommand::List => {
            let default = project.config.project.default_env.clone();
            for e in list_environments(&project)? {
                let mark = if Some(&e.name) == default.as_ref() {
                    " (default)"
                } else {
                    ""
                };
                let secrets = e
                    .secrets_file
                    .as_ref()
                    .map(|s| format!(" + {}", s.display()))
                    .unwrap_or_default();
                println!("{}{mark}\t{}{secrets}", e.name, e.file.display());
            }
        }
        EnvCommand::Vars {
            file,
            vars,
            show_secrets,
        } => {
            let rel = file
                .as_ref()
                .map(|f| request_rel(&project, cli_dir, f))
                .transpose()?;
            let layers = Layers {
                cli: parse_cli_vars(&vars.vars)?,
                ..Default::default()
            };
            let ctx = var_context(&project, rel.as_deref(), vars.env.as_deref(), layers)?;
            for (name, r) in ctx.effective(&project.root) {
                let value = match (&r.value, r.secret && !show_secrets) {
                    (_, true) => crate::redact::MASK.to_string(),
                    (Some(v), false) => v.clone(),
                    (None, false) => "(unset)".into(),
                };
                println!("{name} = {value}\t# {}", r.location);
            }
        }
    }
    Ok(EXIT_OK)
}

/// Reads a secret value from a hidden prompt (TTY) or all of stdin.
fn read_secret_value(name: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password(format!("Value for {name}: "))?)
    } else {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s.trim_end_matches(['\n', '\r']).to_string())
    }
}

fn cmd_secret(cli_dir: &Option<PathBuf>, cmd: &SecretCommand) -> Result<i32> {
    let project = project_at(cli_dir)?;
    let store = open_store(&project)?;
    let mut index = SecretIndex::load(&project)?;
    let env_or_default = |e: &Option<String>| -> Result<String> {
        e.clone()
            .or(project.config.project.default_env.clone())
            .context("no environment given and no default_env in curly.toml")
    };
    match cmd {
        SecretCommand::Set { name, env } => {
            let env = env_or_default(env)?;
            crate::vars::find_environment(&project, &env)?;
            let value = read_secret_value(name)?;
            if value.is_empty() {
                bail!("empty value; nothing stored");
            }
            store.set(&env, name, &value)?;
            index.update(&env, name, true)?;
            eprintln!("stored {name} for environment {env} in {}", store.backend());
        }
        SecretCommand::Get { name, env } => {
            let env = env_or_default(env)?;
            let v = store
                .get(&env, name)?
                .with_context(|| format!("no secret {name} for environment {env}"))?;
            println!("{v}");
        }
        SecretCommand::Rm { name, env } => {
            let env = env_or_default(env)?;
            let existed = store.delete(&env, name)?;
            index.update(&env, name, false)?;
            eprintln!(
                "{}",
                if existed {
                    format!("deleted {name} from {env}")
                } else {
                    format!("{name} was not stored for {env}")
                }
            );
        }
        SecretCommand::List { env } => {
            for (e, names) in &index.envs {
                if env.as_ref().is_none_or(|want| want == e) {
                    for n in names {
                        println!("{e}\t{n}");
                    }
                }
            }
        }
    }
    Ok(EXIT_OK)
}

fn to_query(text: Option<String>, f: &HistoryFilter) -> Result<Query> {
    Ok(Query {
        text,
        status: f.status.clone(),
        method: f.method.clone(),
        file: f.file.clone(),
        env: f.env.clone(),
        since: f.since.as_deref().map(parse_since).transpose()?,
        limit: f.limit,
    })
}

fn print_entries(entries: &[Entry], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(entries)?);
        return Ok(());
    }
    let p = Paint {
        on: use_color(false),
    };
    for e in entries {
        let status = match &e.exchange.response {
            Some(r) => p.status(r.status, &r.status.to_string()),
            None => p.red("ERR"),
        };
        let ts = e.ts.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S");
        let target = e
            .file
            .clone()
            .unwrap_or_else(|| e.exchange.request.url.clone());
        println!(
            "{:>5}  {ts}  {:<6} {status}  {:>9}  {target}",
            p.bold(&format!("#{}", e.id)),
            e.exchange.request.method,
            format!("{:.1} ms", e.exchange.timing.total_ms)
        );
    }
    Ok(())
}

fn cmd_history(cli_dir: &Option<PathBuf>, cmd: &HistoryCommand) -> Result<i32> {
    let project = project_at(cli_dir)?;
    let h = open_history(&project)?;
    match cmd {
        HistoryCommand::List { filter } => {
            print_entries(&h.search(&to_query(None, filter)?)?, filter.json)?
        }
        HistoryCommand::Search { text, filter } => print_entries(
            &h.search(&to_query(Some(text.clone()), filter)?)?,
            filter.json,
        )?,
        HistoryCommand::Show { id, view, json } => {
            if view.tui {
                crate::tui::require_terminal()?;
            }
            let e = h.get(entry_id(&h, id)?)?;
            if view.tui {
                crate::tui::view_exchange(
                    format!("#{} {}", e.id, e.file.clone().unwrap_or_default()),
                    e.exchange,
                )?;
            } else if *json {
                println!("{}", serde_json::to_string_pretty(&e)?);
            } else {
                let opts = view.options();
                if opts.mode == Mode::Full && opts.filter.is_none() {
                    let p = Paint { on: opts.color };
                    let ts = e.ts.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S");
                    let mut header = format!("#{}  {ts}", e.id);
                    if let Some(env) = &e.env {
                        header.push_str(&format!("  env={env}"));
                    }
                    if let Some(f) = &e.file {
                        header.push_str(&format!("  {f}"));
                    }
                    if e.body_truncated {
                        header.push_str("  (body truncated)");
                    }
                    println!("{}", p.dim(&header));
                }
                write_out(&render(&e.exchange, &opts)?)?;
            }
        }
        HistoryCommand::Diff {
            a,
            b,
            ignore,
            all_headers,
            plain,
        } => {
            let (a, b) = (h.get(entry_id(&h, a)?)?, h.get(entry_id(&h, b)?)?);
            let mut ignore = ignore.clone();
            if !all_headers {
                ignore.push("date".into());
            }
            let d = history::diff(&a, &b, &ignore, use_color(*plain));
            if d.is_empty() {
                println!("responses #{} and #{} are identical", a.id, b.id);
            } else {
                write_out(d.as_bytes())?;
                return Ok(EXIT_FAILED);
            }
        }
        HistoryCommand::Rerun {
            id,
            vars,
            view,
            show_secrets,
        } => {
            let e = h.get(entry_id(&h, id)?)?;
            if view.tui {
                crate::tui::require_terminal()?;
            }
            let result = rerun_entry(&project, &e, &parse_cli_vars(vars)?, *show_secrets)?;
            if view.tui {
                crate::tui::view_exchange(format!("re-run of #{}", e.id), result.exchange)?;
                return Ok(EXIT_OK);
            }
            let vo = view.options();
            if result.exchange.response.is_none() {
                eprint!(
                    "{}",
                    String::from_utf8_lossy(&render(&result.exchange, &vo)?)
                );
            } else {
                write_out(&render(&result.exchange, &vo)?)?;
            }
            if let Some(new_id) = result.history_id {
                eprintln!(
                    "{}",
                    Paint { on: vo.color }.dim(&format!("history #{new_id} (re-run of #{})", e.id))
                );
            }
            if result.exchange.response.is_none() {
                return Ok(EXIT_TRANSPORT);
            }
        }
        HistoryCommand::Save { id, force } => {
            let e = h.get(entry_id(&h, id)?)?;
            let file = e
                .file
                .clone()
                .context("entry has no request file to attach an example to")?;
            let resp = e
                .exchange
                .response
                .as_ref()
                .context("entry has no response (the request failed)")?;
            let rel = PathBuf::from(&file);
            let target = crate::mock::example_path(
                &rel,
                (!(200..300).contains(&resp.status)).then_some(resp.status),
            );
            if project.root.join(&target).exists() && !force {
                bail!("{} exists (use --force to overwrite)", target.display());
            }
            let mut headers = std::collections::BTreeMap::new();
            for (k, v) in &resp.headers {
                if ["content-type", "location"].contains(&k.to_ascii_lowercase().as_str()) {
                    headers.insert(k.to_ascii_lowercase(), v.clone());
                }
            }
            let is_json = resp.content_type().is_some_and(|c| c.contains("json"));
            let body = match serde_json::from_slice::<serde_json::Value>(&resp.body) {
                Ok(v) if is_json || resp.content_type().is_none() => v,
                _ if resp.body.is_empty() => serde_json::Value::Null,
                _ => serde_json::Value::String(String::from_utf8_lossy(&resp.body).into_owned()),
            };
            let canned = crate::mock::Canned {
                status: resp.status,
                headers,
                body,
            };
            std::fs::write(
                project.root.join(&target),
                serde_json::to_string_pretty(&canned)? + "\n",
            )?;
            println!(
                "saved #{} as {}{}",
                e.id,
                target.display(),
                if e.redacted { " (redacted)" } else { "" }
            );
        }
        HistoryCommand::Prune {
            keep,
            older_than,
            all,
        } => {
            let n = if *all {
                h.clear()?
            } else {
                h.prune(*keep, older_than.as_deref().map(parse_since).transpose()?)?
            };
            println!("deleted {n} entries");
        }
    }
    Ok(EXIT_OK)
}

/// Writes the registration script for `shell`, pointing at this executable.
fn cmd_completion(shell: &str) -> Result<i32> {
    let shells = Shells::builtins();
    let completer = shells
        .completer(shell)
        .with_context(|| format!("unsupported shell `{shell}`"))?;
    let argv0 = std::env::args_os()
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("curly"));
    let exe = if argv0.components().count() > 1 {
        std::env::current_exe()?
    } else {
        argv0
    };
    let mut out = Vec::new();
    completer.write_registration(
        "COMPLETE",
        "curly",
        "curly",
        &exe.to_string_lossy(),
        &mut out,
    )?;
    write_out(&out)?;
    Ok(EXIT_OK)
}

/// Runs the CLI and returns the process exit code.
pub fn main() -> i32 {
    CompleteEnv::with_factory(Cli::command).complete();
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Init { dir, name } => (|| {
            let dir = dir
                .clone()
                .or(cli.dir.clone())
                .unwrap_or_else(|| PathBuf::from("."));
            for f in project::init(
                &dir,
                &project::InitOptions {
                    name: name.as_deref(),
                    ..Default::default()
                },
            )? {
                println!("created {}", f.display());
            }
            Ok(EXIT_OK)
        })(),
        Command::Run(args) => cmd_run(&cli.dir, args),
        Command::Cmd { file, vars } => (|| {
            let project = project_at(&cli.dir)?;
            let rel = request_rel(&project, &cli.dir, file)?;
            if crate::request::is_ws(&rel) {
                bail!(
                    "{} is a WebSocket request; use `curly ws {}` (curl can open WebSockets but cannot script messages)",
                    rel.display(),
                    rel.display()
                );
            }
            if crate::request::is_grpc(&rel) {
                bail!(
                    "{} is a gRPC request; use `curly run {}` (curl cannot frame gRPC messages)",
                    rel.display(),
                    rel.display()
                );
            }
            let (cmd, exports) = plain_command(
                &project,
                &rel,
                vars.env.as_deref(),
                &parse_cli_vars(&vars.vars)?,
            )?;
            println!(
                "cd {}",
                crate::curlexec::shell_join(&[project.root.display().to_string()])
            );
            for line in exports {
                println!("{line}");
            }
            println!("{cmd}");
            Ok(EXIT_OK)
        })(),
        Command::Lint { paths, vars } => cmd_lint(&cli.dir, paths, vars),
        Command::Import(cmd) => cmd_import(&cli.dir, cmd),
        Command::Auth(cmd) => cmd_auth(&cli.dir, cmd),
        Command::Gql(cmd) => cmd_gql(&cli.dir, cmd),
        Command::Grpc(cmd) => cmd_grpc(&cli.dir, cmd),
        Command::New {
            path,
            stdin,
            name,
            literal,
            no_store_secrets,
            env,
            force,
            command,
        } => (|| {
            let project = project_at(&cli.dir)?;
            let words = command_words(command, *stdin)?;
            let saved = save_command(
                &project,
                &cli.dir,
                path,
                &words,
                name.clone(),
                *literal,
                !no_store_secrets,
                env.as_deref(),
                *force,
            )?;
            report_saved(&project, &saved, env.as_deref())?;
            Ok(EXIT_OK)
        })(),
        Command::Curl(args) => cmd_curl(&cli.dir, args),
        Command::Fmt { paths, check } => cmd_fmt(&cli.dir, paths, *check),
        Command::Tui { id } => (|| {
            crate::tui::require_terminal()?;
            let project = project_at(&cli.dir)?;
            let h = open_history(&project)?;
            if let Some(id) = id {
                let e = h.get(entry_id(&h, id)?)?;
                crate::tui::view_exchange(
                    format!("#{} {}", e.id, e.file.clone().unwrap_or_default()),
                    e.exchange,
                )?;
                return Ok(EXIT_OK);
            }
            let load = || {
                h.search(&Query {
                    limit: 500,
                    ..Default::default()
                })
            };
            let entries = load()?;
            let mut rerun = |id: i64| -> Result<String> {
                let e = h.get(id)?;
                let r = rerun_entry(&project, &e, &[], false)?;
                let status = r
                    .exchange
                    .response
                    .as_ref()
                    .map(|x| x.status.to_string())
                    .unwrap_or_else(|| "error".into());
                Ok(format!(
                    "re-ran #{id} as #{}: {status}",
                    r.history_id.unwrap_or_default()
                ))
            };
            crate::tui::browse_history(entries, &mut rerun, &mut || load())?;
            Ok(EXIT_OK)
        })(),
        Command::Docs {
            paths,
            format,
            out,
            env,
        } => (|| {
            let project = project_at(&cli.dir)?;
            let targets: Vec<PathBuf> = if paths.is_empty() {
                vec![PathBuf::new()]
            } else {
                paths
                    .iter()
                    .map(|p| request_rel(&project, &cli.dir, p))
                    .collect::<Result<_>>()?
            };
            let doc = crate::docs::collect(&project, &targets, env.as_deref())?;
            let dir = match out {
                Some(o) => cli
                    .dir
                    .as_ref()
                    .filter(|_| o.is_relative())
                    .map(|d| d.join(o))
                    .unwrap_or(o.clone()),
                None => project.root.join("docs"),
            };
            std::fs::create_dir_all(&dir)?;
            let (name, text) = if format == "md" {
                ("index.md", crate::docs::render_markdown(&doc))
            } else {
                ("index.html", crate::docs::render_html(&doc))
            };
            let path = dir.join(name);
            std::fs::write(&path, text)?;
            let count: usize = doc.folders.iter().map(|f| f.requests.len()).sum();
            println!(
                "wrote {} ({count} requests in {} folders)",
                path.display(),
                doc.folders.len()
            );
            Ok(EXIT_OK)
        })(),
        Command::Mock {
            spec,
            examples,
            host,
            port,
            validate,
        } => (|| {
            crate::mock::check_loopback(*host)?;
            let mut routes = Vec::new();
            if let Some(spec) = spec {
                let path = match &cli.dir {
                    Some(d) if spec.is_relative() => d.join(spec),
                    _ => spec.clone(),
                };
                routes.extend(crate::mock::routes_from_spec(
                    &std::fs::read_to_string(&path)
                        .with_context(|| format!("reading {}", path.display()))?,
                )?);
            }
            if *examples || spec.is_none() {
                routes.extend(crate::mock::routes_from_examples(&project_at(&cli.dir)?)?);
            }
            crate::mock::serve(
                routes,
                &crate::mock::MockOptions {
                    host: *host,
                    port: *port,
                    validate: *validate,
                },
            )?;
            Ok(EXIT_OK)
        })(),
        Command::Ws {
            file,
            interactive,
            vars,
            plain,
            show_secrets,
            no_history,
        } => (|| {
            if !*interactive {
                let args = RunArgs {
                    paths: vec![file.clone()],
                    vars: vars.clone(),
                    view: ViewArgs {
                        plain: *plain,
                        ..Default::default()
                    },
                    data: None,
                    bail: false,
                    reports: vec![],
                    responses: false,
                    no_history: *no_history,
                    show_secrets: *show_secrets,
                };
                return cmd_run(&cli.dir, &args);
            }
            let project = project_at(&cli.dir)?;
            let rel = request_rel(&project, &cli.dir, file)?;
            if !crate::request::is_ws(&rel) {
                bail!("{} is not a .ws file", rel.display());
            }
            let curl = Curl::detect(&project.curl_path())?;
            let opts = RunOptions {
                env: vars.env.clone(),
                vars: parse_cli_vars(&vars.vars)?,
                record: !no_history,
                show_secrets: *show_secrets,
                ..Default::default()
            };
            let r = crate::ws::interactive(&project, &curl, &rel, &opts, use_color(*plain))?;
            if let Some(id) = r.history_id {
                eprintln!(
                    "{}",
                    Paint {
                        on: use_color(*plain)
                    }
                    .dim(&format!("history #{id}"))
                );
            }
            Ok(EXIT_OK)
        })(),
        Command::Env(cmd) => cmd_env(&cli.dir, cmd),
        Command::Secret(cmd) => cmd_secret(&cli.dir, cmd),
        Command::History(cmd) => cmd_history(&cli.dir, cmd),
        Command::Completion { shell } => cmd_completion(shell),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            EXIT_USAGE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_since() {
        let now = Utc::now();
        let t = parse_since("2h").unwrap();
        assert!((now - t - Duration::hours(2)).num_seconds().abs() < 5);
        assert!(parse_since("2026-01-01T00:00:00Z").is_ok());
        assert!(parse_since("2x").is_err());
        assert!(parse_since("h").is_err());
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
