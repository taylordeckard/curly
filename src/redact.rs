//! Masks credentials in exchanges before they are printed, stored, or reported.
//!
//! Three layers are applied in order: (1) known secret values are scrubbed
//! anywhere they appear; (2) sensitive headers are masked (keeping the auth
//! scheme); (3) sensitive JSON keys and URL query parameters are masked.

use std::collections::HashSet;

use anyhow::{Context, Result};
use regex::Regex;

use crate::curlexec::Exchange;
use crate::project::RedactSection;
use crate::vars::MIN_SECRET_LEN;

/// Replacement text for masked values.
pub const MASK: &str = "[REDACTED]";

const DEFAULT_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
];
const DEFAULT_KEYS: &str =
    r"(?i)(token|secret|password|passwd|api_?key|credentials?|private_?key|session_?id)$";
const DEFAULT_PARAMS: &str = r"(?i)^(access_token|refresh_token|id_token|token|api_?key|key|secret|client_secret|password|sig|signature)$";

/// Applies redaction rules.
#[derive(Debug, Clone)]
pub struct Redactor {
    headers: HashSet<String>,
    json_keys: Vec<Regex>,
    query_params: Vec<Regex>,
    secrets: Vec<(String, String)>,
}

impl Redactor {
    /// Builds a redactor from config plus known `(name, value)` secrets.
    pub fn new(cfg: &RedactSection, secrets: Vec<(String, String)>) -> Result<Redactor> {
        let compile = |default: &str, extra: &[String]| -> Result<Vec<Regex>> {
            std::iter::once(default.to_string())
                .chain(extra.iter().cloned())
                .map(|p| Regex::new(&p).with_context(|| format!("invalid [redact] pattern `{p}`")))
                .collect()
        };
        let mut secrets: Vec<_> = secrets
            .into_iter()
            .filter(|(_, v)| v.len() >= MIN_SECRET_LEN)
            .collect();
        secrets.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
        secrets.dedup_by(|a, b| a.1 == b.1);
        Ok(Redactor {
            headers: DEFAULT_HEADERS
                .iter()
                .map(|h| h.to_string())
                .chain(cfg.headers.iter().map(|h| h.to_ascii_lowercase()))
                .collect(),
            json_keys: compile(DEFAULT_KEYS, &cfg.json_keys)?,
            query_params: compile(DEFAULT_PARAMS, &cfg.query_params)?,
            secrets,
        })
    }

    /// Replaces every known secret value in `text`.
    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (name, value) in &self.secrets {
            if out.contains(value.as_str()) {
                out = out.replace(value.as_str(), &format!("[REDACTED:{name}]"));
            }
        }
        out
    }

    /// Masks a header value if the header is sensitive; keeps the auth scheme word.
    pub fn header_value(&self, name: &str, value: &str) -> String {
        if !self.headers.contains(&name.to_ascii_lowercase()) {
            return self.scrub(value);
        }
        if (name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("proxy-authorization"))
            && let Some((scheme, _)) = value.split_once(' ')
        {
            return format!("{scheme} {MASK}");
        }
        MASK.into()
    }

    /// Masks sensitive query parameters and secret values in a URL.
    pub fn url(&self, url: &str) -> String {
        let url = self.scrub(url);
        let Some((base, rest)) = url.split_once('?') else {
            return url;
        };
        let (query, fragment) = match rest.split_once('#') {
            Some((q, f)) => (q, Some(f)),
            None => (rest, None),
        };
        let query: Vec<String> = query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, _)) if self.query_params.iter().any(|r| r.is_match(k)) => {
                    format!("{k}={MASK}")
                }
                _ => pair.to_string(),
            })
            .collect();
        let mut out = format!("{base}?{}", query.join("&"));
        if let Some(f) = fragment {
            out.push('#');
            out.push_str(f);
        }
        out
    }

    fn json_value(&self, v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    if self.json_keys.iter().any(|r| r.is_match(k))
                        && !val.is_object()
                        && !val.is_array()
                        && !val.is_null()
                    {
                        *val = serde_json::Value::String(MASK.into());
                    } else {
                        self.json_value(val);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(|i| self.json_value(i)),
            serde_json::Value::String(s) => *s = self.scrub(s),
            _ => {}
        }
    }

    /// Masks a body: JSON keys if it parses as JSON, form fields if it looks
    /// like a urlencoded form, secret values otherwise. Binary is left as-is
    /// apart from secret scrubbing of valid UTF-8.
    pub fn body(&self, body: &[u8], content_type: Option<&str>) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(body) else {
            return body.to_vec();
        };
        if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text)
            && (v.is_object() || v.is_array())
        {
            let original = v.clone();
            self.json_value(&mut v);
            if v == original {
                return body.to_vec();
            }
            let pretty = text.trim_start().starts_with(['{', '[']) && text.contains('\n');
            let out = if pretty {
                serde_json::to_string_pretty(&v)
            } else {
                serde_json::to_string(&v)
            };
            return out.unwrap_or_default().into_bytes();
        }
        if content_type.is_some_and(|c| c.contains("x-www-form-urlencoded")) {
            return self.url(&format!("?{text}")).as_bytes()[1..].to_vec();
        }
        self.scrub(text).into_bytes()
    }

    /// Returns a redacted copy of an exchange.
    pub fn exchange(&self, ex: &Exchange) -> Exchange {
        let mut out = ex.clone();
        out.request.url = self.url(&ex.request.url);
        let req_ct = ex
            .request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());
        out.request.headers = ex
            .request
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), self.header_value(k, v)))
            .collect();
        out.request.body = self.body(&ex.request.body, req_ct.as_deref());
        if let Some(r) = out.response.as_mut() {
            let ct = r.content_type().map(str::to_string);
            r.headers = r
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), self.header_value(k, v)))
                .collect();
            r.body = self.body(&r.body, ct.as_deref());
        }
        out.error = ex.error.as_deref().map(|e| self.scrub(e));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curlexec::{RequestRecord, ResponseRecord};

    fn redactor() -> Redactor {
        Redactor::new(
            &RedactSection::default(),
            vec![
                ("API_TOKEN".into(), "tok-123456".into()),
                ("SHORT".into(), "ab".into()),
            ],
        )
        .unwrap()
    }

    #[test]
    fn masks_headers_keeping_scheme() {
        let r = redactor();
        assert_eq!(
            r.header_value("Authorization", "Bearer abc"),
            "Bearer [REDACTED]"
        );
        assert_eq!(r.header_value("Cookie", "a=b"), MASK);
        assert_eq!(
            r.header_value("X-Trace", "has tok-123456 inside"),
            "has [REDACTED:API_TOKEN] inside"
        );
        assert_eq!(
            r.header_value("Accept", "ab"),
            "ab",
            "short secrets are not scrubbed"
        );
    }

    #[test]
    fn masks_query_params() {
        let r = redactor();
        assert_eq!(
            r.url("http://h/p?a=1&access_token=xyz&key=k#frag"),
            "http://h/p?a=1&access_token=[REDACTED]&key=[REDACTED]#frag"
        );
        assert_eq!(
            r.url("http://h/tok-123456"),
            "http://h/[REDACTED:API_TOKEN]"
        );
    }

    #[test]
    fn masks_json_keys_recursively() {
        let r = redactor();
        let body = br#"{"access_token":"x","accessToken":"y","token_type":"Bearer","nested":{"password":"p","list":[{"client_secret":"s"}]},"note":"tok-123456","count":1}"#;
        let out: serde_json::Value =
            serde_json::from_slice(&r.body(body, Some("application/json"))).unwrap();
        assert_eq!(out["access_token"], MASK);
        assert_eq!(out["accessToken"], MASK);
        assert_eq!(out["token_type"], "Bearer");
        assert_eq!(out["nested"]["password"], MASK);
        assert_eq!(out["nested"]["list"][0]["client_secret"], MASK);
        assert_eq!(out["note"], "[REDACTED:API_TOKEN]");
        assert_eq!(out["count"], 1);
    }

    #[test]
    fn masks_form_bodies_and_whole_exchange() {
        let r = redactor();
        let ex = Exchange {
            request: RequestRecord {
                method: "POST".into(),
                url: "http://h/?token=t".into(),
                headers: vec![
                    ("Authorization".into(), "Basic dXNlcjpwYXNz".into()),
                    (
                        "Content-Type".into(),
                        "application/x-www-form-urlencoded".into(),
                    ),
                ],
                body: b"user=a&password=hunter22".to_vec(),
            },
            response: Some(ResponseRecord {
                status: 200,
                headers: vec![("Set-Cookie".into(), "sid=1".into())],
                body: b"plain tok-123456".to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let out = r.exchange(&ex);
        assert_eq!(out.request.url, "http://h/?token=[REDACTED]");
        assert_eq!(out.request.headers[0].1, "Basic [REDACTED]");
        assert_eq!(out.request.body, b"user=a&password=[REDACTED]");
        let resp = out.response.unwrap();
        assert_eq!(resp.headers[0].1, MASK);
        assert_eq!(resp.body, b"plain [REDACTED:API_TOKEN]");
    }
}
