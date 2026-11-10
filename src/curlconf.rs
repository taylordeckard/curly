//! Parser for curl config files (`curl -K`), `# @key` metadata comments, and a
//! catalog of options supported by the installed curl.
//!
//! The parser follows curl's own rules (tool_parsecfg.c): `#` starts a comment
//! only at the beginning of a line; an option is followed by optional `=`/`:`
//! and a value that is either double-quoted (with `\"`, `\\`, `\t`, `\n`, `\r`,
//! `\v` escapes) or runs to the next whitespace.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;

/// One option line from a config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 1-based line number.
    pub line: usize,
    /// Long option name without leading dashes (short options keep their dash, e.g. `-H`).
    pub option: String,
    /// Parsed value, if any.
    pub value: Option<String>,
}

/// `# @key value` metadata carried in comments.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Metadata {
    /// `@name`: display name.
    pub name: Option<String>,
    /// `@description`: free text; continuation lines are indented comments.
    pub description: Option<String>,
    /// `@tags`: comma-separated tags.
    pub tags: Vec<String>,
    /// Any other `@key value` pairs.
    pub other: BTreeMap<String, String>,
}

/// A parsed config file.
#[derive(Debug, Clone, Default)]
pub struct ConfigFile {
    /// Option lines in order.
    pub entries: Vec<Entry>,
    /// Metadata from comments.
    pub meta: Metadata,
    /// Syntax errors as `(line, message)`.
    pub errors: Vec<(usize, String)>,
}

/// Short options curl accepts in config files, mapped to long names.
static SHORT_OPTIONS: &[(&str, &str)] = &[
    ("-A", "user-agent"),
    ("-b", "cookie"),
    ("-c", "cookie-jar"),
    ("-d", "data"),
    ("-D", "dump-header"),
    ("-e", "referer"),
    ("-E", "cert"),
    ("-f", "fail"),
    ("-F", "form"),
    ("-G", "get"),
    ("-H", "header"),
    ("-i", "include"),
    ("-I", "head"),
    ("-k", "insecure"),
    ("-K", "config"),
    ("-L", "location"),
    ("-m", "max-time"),
    ("-o", "output"),
    ("-O", "remote-name"),
    ("-s", "silent"),
    ("-S", "show-error"),
    ("-T", "upload-file"),
    ("-u", "user"),
    ("-v", "verbose"),
    ("-w", "write-out"),
    ("-x", "proxy"),
    ("-X", "request"),
];

/// Matches `{{name}}` or `{{name:fn:fn}}` references in `expand-*` values.
static VAR_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{([A-Za-z0-9_]+)((?::[A-Za-z0-9]+)*)\}\}").expect("regex"));

impl Entry {
    /// Long option name with short options mapped (`-H` -> `header`).
    pub fn long_name(&self) -> &str {
        if self.option.starts_with('-') {
            SHORT_OPTIONS
                .iter()
                .find(|(s, _)| *s == self.option)
                .map(|(_, l)| *l)
                .unwrap_or(&self.option)
        } else {
            &self.option
        }
    }

    /// Option name with any `expand-` prefix removed.
    pub fn base_name(&self) -> &str {
        let n = self.long_name();
        n.strip_prefix("expand-").unwrap_or(n)
    }

    /// True for `--expand-*` options, whose values undergo `{{var}}` expansion.
    pub fn is_expanded(&self) -> bool {
        self.long_name().starts_with("expand-")
    }
}

/// Parses a double-quoted value starting after the opening quote. Returns the
/// value and the remainder, or `None` if the closing quote is missing.
fn parse_quoted(s: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, &s[i + 1..])),
            '\\' => match chars.next() {
                Some((_, 't')) => out.push('\t'),
                Some((_, 'n')) => out.push('\n'),
                Some((_, 'r')) => out.push('\r'),
                Some((_, 'v')) => out.push('\u{0b}'),
                Some((_, other)) => out.push(other),
                None => return None,
            },
            _ => out.push(c),
        }
    }
    None
}

/// Applies a metadata comment body (text after `#`) to `meta`.
fn apply_metadata(meta: &mut Metadata, last_key: &mut Option<String>, body: &str) {
    if let Some(rest) = body.trim_start().strip_prefix('@') {
        let (key, value) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let value = value.trim().to_string();
        match key {
            "name" => meta.name = Some(value),
            "description" => meta.description = Some(value),
            "tags" => {
                meta.tags = value
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            }
            _ => {
                meta.other.insert(key.to_string(), value);
            }
        }
        *last_key = Some(key.to_string());
    } else if body.starts_with("  ") && last_key.as_deref() == Some("description") {
        let d = meta.description.get_or_insert_with(String::new);
        if !d.is_empty() {
            d.push('\n');
        }
        d.push_str(body.trim());
    } else {
        *last_key = None;
    }
}

/// Parses curl config text.
pub fn parse(src: &str) -> ConfigFile {
    let mut cfg = ConfigFile::default();
    let mut last_key: Option<String> = None;
    for (idx, raw) in src.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_start();
        if line.is_empty() {
            last_key = None;
            continue;
        }
        if let Some(body) = line.strip_prefix('#') {
            apply_metadata(&mut cfg.meta, &mut last_key, body);
            continue;
        }
        last_key = None;
        let end = line
            .find(|c: char| c.is_whitespace() || c == '=' || c == ':')
            .unwrap_or(line.len());
        let opt = &line[..end];
        let option = if let Some(long) = opt.strip_prefix("--") {
            long.to_string()
        } else {
            opt.to_string()
        };
        let mut rest = line[end..].trim_start();
        if let Some(r) = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')) {
            rest = r.trim_start();
        }
        let value = if rest.is_empty() {
            None
        } else if let Some(q) = rest.strip_prefix('"') {
            match parse_quoted(q) {
                Some((v, _)) => Some(v),
                None => {
                    cfg.errors
                        .push((line_no, format!("unterminated quoted value for `{option}`")));
                    continue;
                }
            }
        } else {
            Some(
                rest.split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
            )
        };
        cfg.entries.push(Entry {
            line: line_no,
            option,
            value,
        });
    }
    cfg
}

/// Reads and parses a config file from disk.
pub fn parse_file(path: &Path) -> Result<ConfigFile> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(parse(&text))
}

/// Escapes `s` as a double-quoted curl config value.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{0b}' => out.push_str("\\v"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A value as written on a flag line: bare when that parses back unchanged,
/// otherwise double-quoted.
fn flag_value(v: &str) -> String {
    let bare_ok = !v.is_empty()
        && !v.starts_with('"')
        && !v
            .chars()
            .any(|c| c.is_whitespace() || c == '\\' || c == '"');
    if bare_ok { v.to_string() } else { quote(v) }
}

/// One config line in command-line style: `--header "Accept: x"` or `--location`.
/// Short options are written with their long name.
pub fn flag_line(option: &str, value: Option<&str>) -> String {
    let long = if option.starts_with('-') && !option.starts_with("--") {
        SHORT_OPTIONS
            .iter()
            .find(|(s, _)| *s == option)
            .map(|(_, l)| *l)
            .unwrap_or(option.trim_start_matches('-'))
    } else {
        option.trim_start_matches('-')
    };
    match value {
        Some(v) => format!("--{long} {}", flag_value(v)),
        None => format!("--{long}"),
    }
}

/// Rewrites config text in command-line style (`--header "x"`), keeping
/// comments, blank lines, order, and lines that do not parse.
pub fn format_flags(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let rewritten = if trimmed.is_empty() || trimmed.starts_with('#') {
            None
        } else {
            let cfg = parse(line);
            match (cfg.errors.is_empty(), cfg.entries.as_slice()) {
                (true, [e]) => Some(flag_line(&e.option, e.value.as_deref())),
                _ => None,
            }
        };
        out.push_str(rewritten.as_deref().unwrap_or(line));
        out.push('\n');
    }
    out
}

/// Returns the variable names referenced as `{{name}}` in `text`.
pub fn var_refs(text: &str) -> Vec<String> {
    VAR_REF
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .collect()
}

/// Functions curl applies in `{{name:fn}}` references.
pub const VAR_FUNCTIONS: &[&str] = &["trim", "json", "url", "b64"];

/// `(name, function)` for each `{{name:fn}}` in `text` whose function curl
/// does not have (often a default value written as `{{name:5}}`).
pub fn unknown_var_functions(text: &str) -> Vec<(String, String)> {
    VAR_REF
        .captures_iter(text)
        .flat_map(|c| {
            let name = c[1].to_string();
            c[2].split(':')
                .filter(|f| !f.is_empty() && !VAR_FUNCTIONS.contains(f))
                .map(|f| (name.clone(), f.to_string()))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Replaces `{{name}}` references with values from `vars`, supporting curl's
/// `trim` and `json` functions. Unknown variables and functions are errors.
pub fn substitute(text: &str, vars: &BTreeMap<String, String>) -> Result<String, String> {
    let mut err = None;
    let out = VAR_REF.replace_all(text, |c: &regex::Captures<'_>| {
        let Some(mut v) = vars.get(&c[1]).cloned() else {
            err.get_or_insert_with(|| format!("`{{{{{}}}}}` is not defined", &c[1]));
            return String::new();
        };
        for f in c[2].split(':').filter(|f| !f.is_empty()) {
            match f {
                "trim" => v = v.trim().to_string(),
                "json" => {
                    v = serde_json::to_string(&v)
                        .map(|s| s[1..s.len() - 1].to_string())
                        .unwrap_or_default()
                }
                "url" => v = crate::oauth::percent_encode(&v),
                "b64" => {
                    use base64::Engine;
                    v = base64::engine::general_purpose::STANDARD.encode(v.as_bytes());
                }
                other => {
                    err.get_or_insert_with(|| format!("function `{other}` is not supported here"));
                }
            }
        }
        v
    });
    match err {
        Some(e) => Err(e),
        None => Ok(out.into_owned()),
    }
}

/// Options that set or add a request body.
pub const BODY_OPTIONS: &[&str] = &[
    "data",
    "data-ascii",
    "data-binary",
    "data-raw",
    "data-urlencode",
    "json",
    "form",
    "form-string",
    "upload-file",
    "get",
];

/// Re-renders `cfg` as config text without options whose base name is in `skip`.
pub fn render_without(cfg: &ConfigFile, skip: &[&str]) -> String {
    let mut out = String::new();
    for e in cfg
        .entries
        .iter()
        .filter(|e| !skip.contains(&e.base_name()))
    {
        match (&e.value, e.option.starts_with('-')) {
            (Some(v), true) => out.push_str(&format!("{} {}\n", e.option, quote(v))),
            (Some(v), false) => out.push_str(&format!("{} = {}\n", e.option, quote(v))),
            (None, _) => out.push_str(&format!("{}\n", e.option)),
        }
    }
    out
}

/// Summary of what a request file will send.
#[derive(Debug, Clone, Default)]
pub struct RequestSpec {
    /// Collection-relative path of the file.
    pub path: PathBuf,
    /// Metadata from comments.
    pub meta: Metadata,
    /// HTTP method curl will use (explicit or inferred).
    pub method: String,
    /// URL template (unexpanded) of the first URL.
    pub url: Option<String>,
    /// Number of URLs in the file (more than one is rejected).
    pub url_count: usize,
    /// Whether the file uses `next` to start a second transfer.
    pub has_next: bool,
    /// Header values in order.
    pub headers: Vec<String>,
    /// `variable` definitions made in the file, with line numbers.
    pub variables: Vec<(usize, String)>,
    /// Variables referenced via `{{name}}` in `expand-*` options, with line numbers.
    pub var_refs: Vec<(usize, String)>,
    /// The parsed file.
    pub config: ConfigFile,
}

impl RequestSpec {
    /// Builds a spec from a parsed config file.
    pub fn from_config(path: PathBuf, config: ConfigFile) -> RequestSpec {
        let mut spec = RequestSpec {
            path,
            meta: config.meta.clone(),
            ..Default::default()
        };
        let mut explicit_method = None;
        let mut has_body = false;
        let mut head = false;
        let mut get = false;
        let mut upload = false;
        for e in &config.entries {
            let value = e.value.clone().unwrap_or_default();
            if e.is_expanded() {
                spec.var_refs
                    .extend(var_refs(&value).into_iter().map(|v| (e.line, v)));
            }
            match e.base_name() {
                "url" => {
                    spec.url_count += 1;
                    spec.url.get_or_insert(value);
                }
                "next" => spec.has_next = true,
                "request" => explicit_method = Some(value),
                "header" => spec.headers.push(value),
                "head" => head = true,
                "get" => get = true,
                "upload-file" => upload = true,
                "json" | "data" | "data-ascii" | "data-binary" | "data-raw" | "data-urlencode"
                | "form" | "form-string" => has_body = true,
                "variable" => spec.variables.push((e.line, value)),
                _ => {}
            }
        }
        spec.method = explicit_method.unwrap_or_else(|| {
            if head {
                "HEAD".into()
            } else if get {
                "GET".into()
            } else if has_body {
                "POST".into()
            } else if upload {
                "PUT".into()
            } else {
                "GET".into()
            }
        });
        spec.config = config;
        spec
    }

    /// Loads `root/rel` and builds its spec.
    pub fn load(root: &Path, rel: &Path) -> Result<RequestSpec> {
        Ok(RequestSpec::from_config(
            rel.to_path_buf(),
            parse_file(&root.join(rel))?,
        ))
    }

    /// Display title: `@name`, falling back to the file stem.
    pub fn title(&self) -> String {
        self.meta.name.clone().unwrap_or_else(|| {
            self.path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
    }
}

/// Options accepted by the installed curl, from `curl --help all`.
#[derive(Debug, Clone, Default)]
pub struct OptionCatalog {
    /// Long option name -> whether it takes an argument.
    pub long: HashMap<String, bool>,
    /// Short option (e.g. `-H`) -> long option name.
    pub short: HashMap<String, String>,
}

/// Matches lines such as ` -H, --header <header/@file>  Pass custom header`.
static HELP_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:(-[A-Za-z0-9#:]),\s+)?--([a-z0-9][a-z0-9.-]*)(\s+<[^>]+>)?").expect("regex")
});

impl OptionCatalog {
    /// Parses `curl --help all` output.
    pub fn from_help(help: &str) -> OptionCatalog {
        let mut cat = OptionCatalog::default();
        for line in help.lines() {
            if let Some(c) = HELP_LINE.captures(line) {
                let long = c[2].to_string();
                if let Some(s) = c.get(1) {
                    cat.short.insert(s.as_str().to_string(), long.clone());
                }
                cat.long.insert(long, c.get(3).is_some());
            }
        }
        cat
    }

    /// Runs `curl --help all` and parses it.
    pub fn load(curl: &str) -> Result<OptionCatalog> {
        let out = Command::new(curl)
            .args(["--help", "all"])
            .output()
            .with_context(|| format!("running {curl} --help all"))?;
        Ok(OptionCatalog::from_help(&String::from_utf8_lossy(
            &out.stdout,
        )))
    }

    /// Checks one entry; returns an error message if curl would reject it.
    pub fn check(&self, e: &Entry) -> Option<String> {
        let name: String = if let Some(long) = self.short.get(&e.option) {
            long.clone()
        } else if e.option.starts_with('-') {
            return Some(format!("unknown short option `{}`", e.option));
        } else {
            e.option
                .strip_prefix("expand-")
                .unwrap_or(&e.option)
                .to_string()
        };
        let lookup = self.long.get(&name).copied().or_else(|| {
            name.strip_prefix("no-")
                .and_then(|n| self.long.get(n).map(|_| false))
        });
        match lookup {
            None => Some(format!("unknown curl option `{}`", e.option)),
            Some(true) if e.value.is_none() => Some(format!("option `{}` needs a value", e.option)),
            Some(_) => None,
        }
    }
}

/// Extensions of request files: curl config (`.curl`), WebSocket (`.ws`), and gRPC (`.grpc`).
pub const REQUEST_EXTENSIONS: &[&str] = &["curl", "ws", "grpc"];

/// Whether a file name is a request file.
pub fn is_request_name(name: &str) -> bool {
    REQUEST_EXTENSIONS.iter().any(|ext| {
        name.strip_suffix(ext)
            .is_some_and(|stem| stem.ends_with('.') && stem.len() > 1)
    })
}

/// Recursively lists request files (`.curl`, `.ws`) under `dir`, skipping hidden
/// directories, `envs/`, and `_folder` files. Results are sorted.
pub fn find_requests(root: &Path, dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = BTreeSet::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("reading {}", d.display()))? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name.starts_with('_') {
                continue;
            }
            if path.is_dir() {
                if path != root.join(crate::project::ENVS_DIR) {
                    stack.push(path);
                }
            } else if is_request_name(&name) {
                out.insert(path);
            }
        }
    }
    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_curl_syntax_variants() {
        let cfg = parse(
            "# comment\nurl = \"http://x/a b\"\n--header: \"A: \\\"q\\\"\"\n-H X-Y:1\nlocation\nexpand-data \"{{V:json}}\\n\"\n",
        );
        let opts: Vec<_> = cfg
            .entries
            .iter()
            .map(|e| (e.option.as_str(), e.value.as_deref()))
            .collect();
        assert_eq!(
            opts,
            vec![
                ("url", Some("http://x/a b")),
                ("header", Some("A: \"q\"")),
                ("-H", Some("X-Y:1")),
                ("location", None),
                ("expand-data", Some("{{V:json}}\n"))
            ]
        );
        assert_eq!(cfg.entries[2].long_name(), "header");
        assert!(cfg.errors.is_empty());
    }

    #[test]
    fn reports_unterminated_quotes() {
        let cfg = parse("url = \"http://x\n");
        assert_eq!(cfg.errors.len(), 1);
        assert_eq!(cfg.errors[0].0, 1);
    }

    #[test]
    fn parses_metadata_with_continuations() {
        let cfg = parse(
            "# @name Get user\n# @description First line.\n#   Second line.\n# @tags users, read\n# @owner team-a\n# plain\nurl = x\n",
        );
        assert_eq!(cfg.meta.name.as_deref(), Some("Get user"));
        assert_eq!(
            cfg.meta.description.as_deref(),
            Some("First line.\nSecond line.")
        );
        assert_eq!(cfg.meta.tags, vec!["users", "read"]);
        assert_eq!(
            cfg.meta.other.get("owner").map(String::as_str),
            Some("team-a")
        );
    }

    #[test]
    fn quote_roundtrips() {
        let original = "a \"b\" \\ c\td\ne";
        let cfg = parse(&format!("data = {}\n", quote(original)));
        assert_eq!(cfg.entries[0].value.as_deref(), Some(original));
    }

    #[test]
    fn formats_in_flag_style_without_changing_meaning() {
        let src = "# @name X\nexpand-url = \"{{BASE_URL}}/a b\"\n-H X-A:1\nheader: \"Accept: */*\"\nlocation\nrequest = POST\ndata = \"{\\\"a\\\": \\\"q\\\"}\"\nvariable = %BASE_URL=http://h\nurl = \"unterminated\n";
        let out = format_flags(src);
        assert_eq!(
            out,
            "# @name X\n--expand-url \"{{BASE_URL}}/a b\"\n--header X-A:1\n--header \"Accept: */*\"\n--location\n--request POST\n--data \"{\\\"a\\\": \\\"q\\\"}\"\n--variable %BASE_URL=http://h\nurl = \"unterminated\n"
        );
        let before: Vec<_> = parse(src)
            .entries
            .into_iter()
            .map(|e| (e.long_name().to_string(), e.value))
            .collect();
        let after: Vec<_> = parse(&out)
            .entries
            .into_iter()
            .map(|e| (e.long_name().to_string(), e.value))
            .collect();
        assert_eq!(before, after, "same options and values");
        assert_eq!(format_flags(&out), out, "idempotent");
    }

    #[test]
    fn substitutes_variables() {
        let vars = BTreeMap::from([("a".to_string(), " x\"y ".to_string())]);
        assert_eq!(substitute("<{{a}}>", &vars).unwrap(), "< x\"y >");
        assert_eq!(substitute("<{{a:trim}}>", &vars).unwrap(), "<x\"y>");
        assert_eq!(substitute("{{a:trim:json}}", &vars).unwrap(), "x\\\"y");
        assert!(
            substitute("{{b}}", &vars)
                .unwrap_err()
                .contains("`{{b}}` is not defined")
        );
        assert_eq!(substitute("{{a:trim:url}}", &vars).unwrap(), "x%22y");
        assert_eq!(substitute("{{a:trim:b64}}", &vars).unwrap(), "eCJ5");
        assert!(substitute("{{a:upper}}", &vars).is_err());
    }

    #[test]
    fn spec_infers_method_and_refs() {
        let cfg = parse(
            "expand-url = \"{{BASE_URL}}/users/{{id}}\"\nexpand-header = \"Authorization: Bearer {{TOKEN:trim}}\"\ndata = @body.json\n",
        );
        let spec = RequestSpec::from_config("x.curl".into(), cfg);
        assert_eq!(spec.method, "POST");
        assert_eq!(spec.url_count, 1);
        let refs: Vec<_> = spec.var_refs.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(refs, vec!["BASE_URL", "id", "TOKEN"]);
        let spec = RequestSpec::from_config("x.curl".into(), parse("url = x\n-X DELETE\n"));
        assert_eq!(spec.method, "DELETE");
        let spec = RequestSpec::from_config("x.curl".into(), parse("url = x\nhead\n"));
        assert_eq!(spec.method, "HEAD");
    }

    #[test]
    fn catalog_checks_options() {
        let help = " -H, --header <header/@file> Pass custom header(s) to server\n     --location-trusted  Like --location\n -L, --location      Follow redirects\n     --url <url>  URL to work with\n     --variable <[%]name=text/@file> Set variable\n";
        let cat = OptionCatalog::from_help(help);
        let cfg = parse(
            "url = x\n-H A:1\nexpand-url = y\nlocation\nno-location\nbogus = 1\nheader\n-Z 1\n",
        );
        let errs: Vec<_> = cfg.entries.iter().map(|e| cat.check(e)).collect();
        assert_eq!(errs[..5], [None, None, None, None, None]);
        assert!(errs[5].as_deref().unwrap().contains("unknown curl option"));
        assert!(errs[6].as_deref().unwrap().contains("needs a value"));
        assert!(errs[7].as_deref().unwrap().contains("unknown short option"));
    }
}
