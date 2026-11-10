//! Converts curl command lines (typed, pasted, or "Copy as cURL" from a
//! browser) into request files in command-line style, so requests can be
//! written the way curl is used on the command line.
//!
//! When templating is on, the scheme and host become `{{BASE_URL}}` and
//! credentials become `{{VARIABLES}}`; their values are returned separately so
//! the caller can put them in the secret store. They are never written to the
//! request file.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::Value;

use crate::curlconf::{OptionCatalog, flag_line};
use crate::vars::SecretNames;

/// Options that only control local output; they are dropped from request
/// files because curly sets output per run.
const OUTPUT_OPTIONS: &[&str] = &[
    "silent",
    "show-error",
    "verbose",
    "include",
    "output",
    "remote-name",
    "remote-name-all",
    "write-out",
    "dump-header",
    "trace",
    "trace-ascii",
    "trace-time",
    "trace-ids",
    "stderr",
    "progress-bar",
    "no-progress-meter",
    "create-dirs",
    "output-dir",
    "fail-with-body",
    "styled-output",
];

/// Headers whose values are credentials.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
];

/// Options that carry a request body.
const BODY_OPTIONS: &[&str] = &["data", "data-raw", "data-binary", "data-ascii", "json"];

/// Splits a shell command line into words. Handles `\` line continuations and
/// bash `$'...'` quoting (used by browsers' "Copy as cURL").
pub fn split_command(text: &str) -> Result<Vec<String>> {
    static ANSI_C: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\$'((?:[^'\\]|\\.)*)'").expect("regex"));
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    let converted = ANSI_C.replace_all(&joined, |c: &regex::Captures<'_>| {
        let mut out = String::new();
        let mut chars = c[1].chars();
        while let Some(ch) = chars.next() {
            if ch != '\\' {
                out.push(ch);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other),
                None => {}
            }
        }
        shlex::try_quote(&out)
            .map(|q| q.into_owned())
            .unwrap_or(out)
    });
    let words =
        shlex::split(&converted).context("cannot parse the command (unbalanced quotes?)")?;
    Ok(words)
}

/// A parsed curl option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    /// Long name without dashes (e.g. `header`).
    pub name: String,
    /// Value, if the option takes one.
    pub value: Option<String>,
}

/// Parses curl arguments (with or without a leading `curl`) into options and URLs.
pub fn parse_args(args: &[String], catalog: &OptionCatalog) -> Result<(Vec<Opt>, Vec<String>)> {
    let mut opts = Vec::new();
    let mut urls = Vec::new();
    let mut it = args
        .iter()
        .skip(usize::from(
            args.first()
                .is_some_and(|a| a == "curl" || a.ends_with("/curl")),
        ))
        .peekable();
    let takes_value = |name: &str| {
        catalog.long.get(name).copied().or_else(|| {
            name.strip_prefix("no-")
                .and_then(|n| catalog.long.get(n))
                .map(|_| false)
        })
    };
    while let Some(arg) = it.next() {
        if let Some(long) = arg.strip_prefix("--") {
            if long.is_empty() {
                urls.extend(it.by_ref().cloned());
                break;
            }
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) if takes_value(n).is_some() => (n.to_string(), Some(v.to_string())),
                _ => (long.to_string(), None),
            };
            match takes_value(&name) {
                None => bail!("unknown curl option `--{name}`"),
                Some(true) => {
                    let value = inline
                        .or_else(|| it.next().cloned())
                        .with_context(|| format!("`--{name}` needs a value"))?;
                    opts.push(Opt {
                        name,
                        value: Some(value),
                    });
                }
                Some(false) => opts.push(Opt { name, value: None }),
            }
        } else if arg.len() > 1 && arg.starts_with('-') {
            let chars: Vec<char> = arg[1..].chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let short = format!("-{}", chars[i]);
                let name = catalog
                    .short
                    .get(&short)
                    .cloned()
                    .with_context(|| format!("unknown curl option `{short}`"))?;
                if takes_value(&name) == Some(true) {
                    let rest: String = chars[i + 1..].iter().collect();
                    let value = if rest.is_empty() {
                        it.next()
                            .cloned()
                            .with_context(|| format!("`{short}` needs a value"))?
                    } else {
                        rest
                    };
                    opts.push(Opt {
                        name,
                        value: Some(value),
                    });
                    break;
                }
                opts.push(Opt { name, value: None });
                i += 1;
            }
        } else {
            urls.push(arg.clone());
        }
    }
    Ok((opts, urls))
}

/// Options for [`convert`].
#[derive(Debug, Clone, Default)]
pub struct ConvertOptions {
    /// Replace the host and credentials with variables.
    pub template: bool,
    /// Current value of `BASE_URL` in the environment, if any.
    pub base_url: Option<String>,
    /// `@name` for the file.
    pub name: Option<String>,
}

/// A variable the conversion introduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVar {
    /// Name.
    pub name: String,
    /// Value taken from the command.
    pub value: String,
    /// Whether it is a credential (goes to the secret store, never a file).
    pub secret: bool,
}

/// Result of converting a command.
#[derive(Debug, Clone, Default)]
pub struct Converted {
    /// Request file text in command-line style.
    pub text: String,
    /// Variables introduced by templating.
    pub vars: Vec<NewVar>,
    /// Options dropped because they only affect local output.
    pub dropped: Vec<String>,
}

/// `X-Api-Key` -> `X_API_KEY`.
fn var_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

struct Templater<'a> {
    names: &'a SecretNames,
    vars: Vec<NewVar>,
}

impl Templater<'_> {
    /// Registers a variable for `value`; reuses the name for the same value and
    /// adds a numeric suffix on conflicts.
    fn var(&mut self, base: &str, value: &str, secret: bool) -> String {
        let base = if secret && !self.names.is_secret(base) {
            format!("{base}_TOKEN")
        } else {
            base.to_string()
        };
        let mut name = base.clone();
        let mut n = 2;
        loop {
            match self.vars.iter().find(|v| v.name == name) {
                Some(v) if v.value == value => return name,
                Some(_) => {
                    name = format!("{base}_{n}");
                    n += 1;
                }
                None => break,
            }
        }
        self.vars.push(NewVar {
            name: name.clone(),
            value: value.to_string(),
            secret,
        });
        name
    }

    /// Templates the origin and secret query parameters of a URL. Returns the
    /// new URL and whether it contains variables.
    fn url(&mut self, url: &str, base_url: Option<&str>) -> (String, bool) {
        let mut out = url.to_string();
        let mut templated = false;
        match base_url {
            Some(base) if !base.is_empty() && url.starts_with(base) => {
                out = format!("{{{{BASE_URL}}}}{}", &url[base.len()..]);
                templated = true;
            }
            None => {
                if let Some((scheme, rest)) = url.split_once("://") {
                    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                    let origin = format!("{scheme}://{}", &rest[..host_end]);
                    self.var("BASE_URL", &origin, false);
                    out = format!("{{{{BASE_URL}}}}{}", &rest[host_end..]);
                    templated = true;
                }
            }
            Some(_) => {}
        }
        if let Some((path, query)) = out.clone().split_once('?') {
            let params: Vec<String> = query
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some((k, v)) if !v.is_empty() && self.names.is_secret(k) => {
                        let name = self.var(&var_name(k), v, true);
                        templated = true;
                        format!("{k}={{{{{name}:url}}}}")
                    }
                    _ => pair.to_string(),
                })
                .collect();
            out = format!("{path}?{}", params.join("&"));
        }
        (out, templated)
    }

    /// Templates a credential header; returns the new header text if it changed.
    fn header(&mut self, header: &str) -> Option<String> {
        let (name, value) = header.split_once(':')?;
        let (name, value) = (name.trim(), value.trim());
        let lower = name.to_ascii_lowercase();
        if value.is_empty()
            || !(CREDENTIAL_HEADERS.contains(&lower.as_str()) || self.names.is_secret(name))
        {
            return None;
        }
        if (lower == "authorization" || lower == "proxy-authorization")
            && let Some((scheme, creds)) = value.split_once(' ')
        {
            let prefix = if lower.starts_with("proxy") {
                "PROXY_"
            } else {
                ""
            };
            let var = self.var(&format!("{prefix}{}", var_name(scheme)), creds.trim(), true);
            return Some(format!("{name}: {scheme} {{{{{var}}}}}"));
        }
        let var = self.var(&var_name(name), value, true);
        Some(format!("{name}: {{{{{var}}}}}"))
    }

    /// Templates secret fields in a JSON object body or a form body.
    fn body(&mut self, body: &str) -> Option<String> {
        if let Ok(Value::Object(mut map)) = serde_json::from_str::<Value>(body) {
            let mut changed = false;
            self.json(&mut map, &mut changed);
            return changed.then(|| serde_json::to_string(&Value::Object(map)).unwrap_or_default());
        }
        if body.contains('=') && !body.contains(['{', '\n', ' ']) {
            let mut changed = false;
            let parts: Vec<String> = body
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some((k, v)) if !v.is_empty() && self.names.is_secret(k) => {
                        changed = true;
                        format!("{k}={{{{{}:url}}}}", self.var(&var_name(k), v, true))
                    }
                    _ => pair.to_string(),
                })
                .collect();
            return changed.then(|| parts.join("&"));
        }
        None
    }

    fn json(&mut self, map: &mut serde_json::Map<String, Value>, changed: &mut bool) {
        for (k, v) in map.iter_mut() {
            match v {
                Value::String(s) if !s.is_empty() && self.names.is_secret(k) => {
                    let name = self.var(&var_name(k), s, true);
                    *v = Value::String(format!("{{{{{name}:json}}}}"));
                    *changed = true;
                }
                Value::Object(inner) => self.json(inner, changed),
                _ => {}
            }
        }
    }
}

/// Converts curl arguments into a request file.
pub fn convert(
    args: &[String],
    catalog: &OptionCatalog,
    opts: &ConvertOptions,
    names: &SecretNames,
) -> Result<Converted> {
    let (parsed, mut urls) = parse_args(args, catalog)?;
    let mut lines: Vec<String> = Vec::new();
    let mut dropped = Vec::new();
    let mut t = Templater {
        names,
        vars: Vec::new(),
    };
    for o in parsed {
        let name = o.name.as_str();
        if OUTPUT_OPTIONS.contains(&name) {
            dropped.push(match &o.value {
                Some(v) => format!("--{name} {v}"),
                None => format!("--{name}"),
            });
            continue;
        }
        if name == "next" || name == "config" || name == "parallel" {
            bail!("`--{name}` is not supported: a request file holds exactly one request");
        }
        if name == "url" {
            urls.push(o.value.unwrap_or_default());
            continue;
        }
        let value = o.value.as_deref();
        let line = match (opts.template, name, value) {
            (true, "header", Some(h)) => t.header(h).map(|h| flag_line("expand-header", Some(&h))),
            (true, "user", Some(u)) => u.split_once(':').map(|(user, pass)| {
                let user_var = t.var("API_USER", user, false);
                let pass_var = t.var("API_PASSWORD", pass, true);
                flag_line(
                    "expand-user",
                    Some(&format!("{{{{{user_var}}}}}:{{{{{pass_var}}}}}")),
                )
            }),
            (true, "oauth2-bearer", Some(tok)) => Some(flag_line(
                "expand-oauth2-bearer",
                Some(&format!("{{{{{}}}}}", t.var("BEARER", tok, true))),
            )),
            (true, n, Some(b)) if BODY_OPTIONS.contains(&n) && !b.starts_with('@') => t
                .body(b)
                .map(|b| flag_line(&format!("expand-{n}"), Some(&b))),
            _ => None,
        };
        lines.push(line.unwrap_or_else(|| flag_line(name, value)));
    }
    let url = match urls.as_slice() {
        [u] => u.clone(),
        [] => bail!("the command has no URL"),
        _ => bail!(
            "the command has {} URLs; a request file holds exactly one request",
            urls.len()
        ),
    };
    let (url_line, templated) = if opts.template {
        t.url(&url, opts.base_url.as_deref())
    } else {
        (url.clone(), false)
    };
    let mut text = String::new();
    if let Some(n) = &opts.name {
        text.push_str(&format!("# @name {n}\n"));
    }
    text.push_str(&flag_line(
        if templated { "expand-url" } else { "url" },
        Some(&url_line),
    ));
    text.push('\n');
    for l in lines {
        text.push_str(&l);
        text.push('\n');
    }
    Ok(Converted {
        text,
        vars: t.vars,
        dropped,
    })
}

/// Literal curl config for running `args` as-is (no templating), for `curly curl`.
pub fn literal_config(args: &[String], catalog: &OptionCatalog) -> Result<(String, Vec<String>)> {
    let converted = convert(
        args,
        catalog,
        &ConvertOptions::default(),
        &SecretNames::new(&[])?,
    )?;
    Ok((converted.text, converted.dropped))
}

/// Groups new variables into `(secret, plain)` maps.
pub fn split_vars(vars: &[NewVar]) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut secret = BTreeMap::new();
    let mut plain = BTreeMap::new();
    for v in vars {
        if v.secret { &mut secret } else { &mut plain }.insert(v.name.clone(), v.value.clone());
    }
    (secret, plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> OptionCatalog {
        let help = std::process::Command::new("curl")
            .args(["--help", "all"])
            .output()
            .unwrap();
        OptionCatalog::from_help(&String::from_utf8_lossy(&help.stdout))
    }

    fn words(s: &str) -> Vec<String> {
        split_command(s).unwrap()
    }

    #[test]
    fn splits_pasted_commands() {
        assert_eq!(
            words("curl 'https://h/x' \\\n  -H 'A: b c' \\\n  --data-raw $'{\"a\":\"it\\'s\\n\"}'"),
            vec![
                "curl",
                "https://h/x",
                "-H",
                "A: b c",
                "--data-raw",
                "{\"a\":\"it's\n\"}"
            ]
        );
        assert!(split_command("curl 'unterminated").is_err());
    }

    #[test]
    fn parses_short_clusters_and_values() {
        let (opts, urls) = parse_args(
            &words("curl -sSL -XPOST -H 'A: 1' --max-time 5 --json '{}' https://h/x"),
            &catalog(),
        )
        .unwrap();
        let names: Vec<&str> = opts.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "silent",
                "show-error",
                "location",
                "request",
                "header",
                "max-time",
                "json"
            ]
        );
        assert_eq!(opts[3].value.as_deref(), Some("POST"));
        assert_eq!(urls, vec!["https://h/x"]);
        assert!(
            parse_args(&words("curl --bogus x"), &catalog())
                .unwrap_err()
                .to_string()
                .contains("unknown curl option `--bogus`")
        );
        assert!(parse_args(&words("curl -H"), &catalog()).is_err());
    }

    #[test]
    fn converts_with_templating_and_keeps_secrets_out() {
        let names = SecretNames::new(&[]).unwrap();
        let cmd = "curl -sS -X POST 'https://api.example.test/v1/users?limit=5&api_key=k3y' -H 'Authorization: Bearer eyJhbGc.tok' -H 'Content-Type: application/json' -H 'Cookie: sid=abc' -u alice:pw0rd --data-raw '{\"name\":\"x\",\"password\":\"hunter2\"}' -o out.json";
        let c = convert(
            &words(cmd),
            &catalog(),
            &ConvertOptions {
                template: true,
                base_url: None,
                name: Some("Create user".into()),
            },
            &names,
        )
        .unwrap();
        assert_eq!(
            c.text,
            "# @name Create user\n--expand-url {{BASE_URL}}/v1/users?limit=5&api_key={{API_KEY:url}}\n--request POST\n--expand-header \"Authorization: Bearer {{BEARER_TOKEN}}\"\n--header \"Content-Type: application/json\"\n--expand-header \"Cookie: {{COOKIE}}\"\n--expand-user {{API_USER}}:{{API_PASSWORD}}\n--expand-data-raw \"{\\\"name\\\":\\\"x\\\",\\\"password\\\":\\\"{{PASSWORD:json}}\\\"}\"\n"
        );
        for secret in ["k3y", "eyJhbGc.tok", "sid=abc", "pw0rd", "hunter2"] {
            assert!(!c.text.contains(secret), "{secret} leaked");
        }
        let (secret, plain) = split_vars(&c.vars);
        assert_eq!(
            plain.get("BASE_URL").map(String::as_str),
            Some("https://api.example.test")
        );
        assert_eq!(plain.get("API_USER").map(String::as_str), Some("alice"));
        assert_eq!(
            secret.get("BEARER_TOKEN").map(String::as_str),
            Some("eyJhbGc.tok")
        );
        assert_eq!(secret.get("PASSWORD").map(String::as_str), Some("hunter2"));
        assert_eq!(
            c.dropped,
            vec!["--silent", "--show-error", "--output out.json"]
        );
    }

    #[test]
    fn reuses_existing_base_url_and_rejects_multi_requests() {
        let names = SecretNames::new(&[]).unwrap();
        let opts = ConvertOptions {
            template: true,
            base_url: Some("https://api.example.test/v1".into()),
            name: None,
        };
        let c = convert(
            &words("curl https://api.example.test/v1/users/7"),
            &catalog(),
            &opts,
            &names,
        )
        .unwrap();
        assert_eq!(c.text, "--expand-url {{BASE_URL}}/users/7\n");
        assert!(c.vars.is_empty());
        let other = convert(
            &words("curl https://elsewhere.test/x"),
            &catalog(),
            &opts,
            &names,
        )
        .unwrap();
        assert_eq!(
            other.text, "--url https://elsewhere.test/x\n",
            "a different host stays literal"
        );
        assert!(
            convert(
                &words("curl https://a/1 https://a/2"),
                &catalog(),
                &opts,
                &names
            )
            .is_err()
        );
        assert!(
            convert(
                &words("curl https://a/1 --next https://a/2"),
                &catalog(),
                &opts,
                &names
            )
            .is_err()
        );
        let (literal, _) = literal_config(
            &words("curl -H 'Authorization: Bearer t' https://a/1"),
            &catalog(),
        )
        .unwrap();
        assert_eq!(
            literal,
            "--url https://a/1\n--header \"Authorization: Bearer t\"\n"
        );
    }
}
