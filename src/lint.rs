//! `curly lint`: checks that request files are valid for plain curl and follow
//! the collection rules (one request per file, no env redefinitions, no
//! undefined variables, no hardcoded credentials).

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use crate::curlconf::{self, OptionCatalog, RequestSpec, var_refs};
use crate::vars::{Source, parse_variable_arg};

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Will break or silently change the request.
    Error,
    /// Probably a mistake.
    Warning,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Diagnostic {
    /// Collection-relative file.
    pub file: PathBuf,
    /// 1-based line (0 = whole file).
    pub line: usize,
    /// Severity.
    pub level: Level,
    /// Explanation.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = match self.level {
            Level::Error => "error",
            Level::Warning => "warning",
        };
        write!(
            f,
            "{}:{}: {level}: {}",
            self.file.display(),
            self.line,
            self.message
        )
    }
}

/// Headers whose literal values are credentials.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "cookie",
];

/// Context for linting: which variables exist and how curl parses options.
pub struct LintContext<'a> {
    /// Option catalog from the installed curl (skips option checks when `None`).
    pub catalog: Option<&'a OptionCatalog>,
    /// Variables defined by the environment, secrets, and `--var`.
    pub defined: BTreeSet<String>,
    /// Environment name for messages.
    pub env_name: Option<String>,
}

/// Lints one request file.
pub fn lint_request(spec: &RequestSpec, ctx: &LintContext<'_>) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let mut push = |line: usize, level: Level, message: String| {
        out.push(Diagnostic {
            file: spec.path.clone(),
            line,
            level,
            message,
        })
    };
    for (line, msg) in &spec.config.errors {
        push(*line, Level::Error, msg.clone());
    }
    if let Some(cat) = ctx.catalog {
        for e in &spec.config.entries {
            if let Some(msg) = cat.check(e) {
                push(e.line, Level::Error, msg);
            }
        }
    }
    if spec.url_count == 0 {
        push(0, Level::Error, "no `url` or `expand-url`".into());
    }
    if spec.url_count > 1 || spec.has_next {
        push(
            0,
            Level::Error,
            "a request file must contain exactly one request (no second url or `next`)".into(),
        );
    }
    let mut local = BTreeSet::new();
    for (line, arg) in &spec.variables {
        match parse_variable_arg(arg) {
            Ok((name, source)) => {
                if ctx.defined.contains(&name) {
                    push(
                        *line,
                        Level::Error,
                        format!(
                            "redefines `{name}`, which the environment sets; the request file would win and hide it"
                        ),
                    );
                } else if matches!(source, Source::Env { .. }) {
                    push(
                        *line,
                        Level::Warning,
                        format!(
                            "imports `{name}` from the shell; declare it in an environment file instead"
                        ),
                    );
                }
                local.insert(name);
            }
            Err(e) => push(*line, Level::Error, e.to_string()),
        }
    }
    for (line, name) in &spec.var_refs {
        if !ctx.defined.contains(name) && !local.contains(name) {
            let env = ctx
                .env_name
                .as_deref()
                .map(|e| format!(" in environment `{e}`"))
                .unwrap_or_default();
            push(
                *line,
                Level::Error,
                format!(
                    "`{{{{{name}}}}}` is not defined{env}; curl would expand it to an empty string"
                ),
            );
        }
    }
    for e in spec
        .config
        .entries
        .iter()
        .filter(|e| e.long_name().starts_with("expand-"))
    {
        let Some(value) = &e.value else { continue };
        for (name, f) in curlconf::unknown_var_functions(value) {
            push(
                e.line,
                Level::Error,
                format!(
                    "`{{{{{name}:{f}}}}}`: curl has no `{f}` function (only {}); curl has no inline defaults, so for a default value add `--variable %{name}={f}` to an environment file",
                    curlconf::VAR_FUNCTIONS.join(", ")
                ),
            );
        }
    }
    for e in &spec.config.entries {
        let value = e.value.as_deref().unwrap_or_default();
        let templated = e.is_expanded() && !var_refs(value).is_empty();
        let credential = match e.base_name() {
            "header" | "proxy-header" => value.split_once(':').is_some_and(|(k, v)| {
                CREDENTIAL_HEADERS.contains(&k.trim().to_ascii_lowercase().as_str())
                    && !v.trim().is_empty()
            }),
            "user" | "proxy-user" | "oauth2-bearer" | "cookie" => !value.is_empty(),
            _ => false,
        };
        if credential && !templated {
            push(
                e.line,
                Level::Error,
                format!(
                    "hardcoded credential in `{}`; use `expand-{}` with a secret variable",
                    e.option,
                    e.base_name()
                ),
            );
        }
    }
    out.sort_by_key(|d| (d.line, d.level));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curlconf::parse;

    fn lint(src: &str, defined: &[&str]) -> Vec<String> {
        let spec = RequestSpec::from_config("r.curl".into(), parse(src));
        let ctx = LintContext {
            catalog: None,
            defined: defined.iter().map(|s| s.to_string()).collect(),
            env_name: Some("local".into()),
        };
        lint_request(&spec, &ctx)
            .into_iter()
            .map(|d| d.message)
            .collect()
    }

    #[test]
    fn clean_file_passes() {
        assert!(lint("expand-url = \"{{BASE_URL}}/x\"\nexpand-header = \"Authorization: Bearer {{API_TOKEN}}\"\n", &["BASE_URL", "API_TOKEN"]).is_empty());
    }

    #[test]
    fn explains_inline_default_mistake() {
        let msgs = lint(
            "expand-url = \"{{BASE_URL}}/x?max={{MAX:5}}&q={{BASE_URL:url}}\"\n",
            &["BASE_URL", "MAX"],
        );
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(
            msgs[0].contains("curl has no `5` function") && msgs[0].contains("--variable %MAX=5"),
            "{msgs:?}"
        );
    }

    #[test]
    fn finds_problems() {
        let msgs = lint(
            "expand-url = \"{{BASE_URL}}/{{missing}}\"\nurl = second\nvariable = \"BASE_URL=x\"\nheader = \"Authorization: Bearer abc\"\n",
            &["BASE_URL"],
        );
        assert!(
            msgs.iter().any(|m| m.contains("exactly one request")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.contains("`{{missing}}` is not defined in environment `local`")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter().any(|m| m.contains("redefines `BASE_URL`")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter().any(|m| m.contains("hardcoded credential")),
            "{msgs:?}"
        );
    }

    #[test]
    fn local_file_variables_are_allowed() {
        assert!(
            lint(
                "variable = \"Q@q.graphql\"\nexpand-url = \"x\"\nexpand-data = \"{{Q:json}}\"\n",
                &[]
            )
            .is_empty()
        );
        assert!(
            lint("url = x\nuser = \"me:pw\"\n", &[])
                .iter()
                .any(|m| m.contains("hardcoded credential"))
        );
        assert!(lint("url = x\n", &[]).is_empty());
        assert!(
            lint("header = \"Accept: x\"\n", &[])
                .iter()
                .any(|m| m.contains("no `url`"))
        );
    }
}
