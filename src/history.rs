//! Local request history in `.curly/history.db` (SQLite).
//!
//! Entries are stored already redacted unless redaction was explicitly
//! disabled; the `redacted` column records which.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use similar::TextDiff;

use crate::curlexec::{Exchange, RequestRecord, ResponseRecord, Timing};
use crate::view::{Paint, body_kind, pretty_body};

/// One history entry.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// Row id.
    pub id: i64,
    /// When the request ran.
    pub ts: DateTime<Utc>,
    /// Collection-relative request file.
    pub file: Option<String>,
    /// Environment name.
    pub env: Option<String>,
    /// `--var` overrides; secret ones are stored as `null` and must be re-supplied.
    pub vars: BTreeMap<String, Option<String>>,
    /// SHA-256 of the request file when it ran.
    pub file_sha256: Option<String>,
    /// Whether redaction was applied before storing.
    pub redacted: bool,
    /// Whether the response body was truncated.
    pub body_truncated: bool,
    /// The exchange (bodies omitted from JSON output; see `request_body`/`response_body`).
    pub exchange: Exchange,
    /// Request body as text (lossy UTF-8), for JSON output.
    pub request_body: String,
    /// Response body as text (lossy UTF-8), for JSON output.
    pub response_body: String,
}

/// Filters for listing and searching.
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// Substring matched against URL, file, and response body.
    pub text: Option<String>,
    /// Exact status (`404`) or class (`4xx`).
    pub status: Option<String>,
    /// HTTP method.
    pub method: Option<String>,
    /// Substring of the request file path.
    pub file: Option<String>,
    /// Environment name.
    pub env: Option<String>,
    /// Only entries at or after this time.
    pub since: Option<DateTime<Utc>>,
    /// Maximum rows (newest first).
    pub limit: usize,
}

/// History database handle.
pub struct History {
    conn: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  file TEXT,
  env TEXT,
  vars TEXT NOT NULL DEFAULT '{}',
  file_sha256 TEXT,
  redacted INTEGER NOT NULL,
  method TEXT NOT NULL,
  url TEXT NOT NULL,
  request_headers TEXT NOT NULL,
  request_body BLOB NOT NULL,
  status INTEGER,
  http_version TEXT,
  reason TEXT,
  response_headers TEXT,
  response_body BLOB,
  body_truncated INTEGER NOT NULL DEFAULT 0,
  timing TEXT NOT NULL,
  total_ms REAL NOT NULL,
  curl_exit INTEGER NOT NULL,
  error TEXT,
  response_size INTEGER
);
CREATE INDEX IF NOT EXISTS entries_ts ON entries(ts);
";

/// New-entry metadata.
#[derive(Debug, Clone, Default)]
pub struct NewEntry {
    /// Collection-relative request file.
    pub file: Option<String>,
    /// Environment name.
    pub env: Option<String>,
    /// `--var` overrides (secret values already replaced with `None`).
    pub vars: BTreeMap<String, Option<String>>,
    /// SHA-256 of the request file.
    pub file_sha256: Option<String>,
    /// Whether the exchange was redacted.
    pub redacted: bool,
}

impl History {
    /// Opens (creating if needed) the database at `path`.
    pub fn open(path: &Path) -> Result<History> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.execute_batch(SCHEMA)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(History { conn })
    }

    /// Stores an exchange; bodies longer than `max_body` are truncated.
    pub fn insert(&self, meta: &NewEntry, ex: &Exchange, max_body: usize) -> Result<i64> {
        let resp = ex.response.as_ref();
        let mut body = resp.map(|r| r.body.clone());
        let truncated = body.as_ref().is_some_and(|b| b.len() > max_body);
        if let Some(b) = body.as_mut() {
            b.truncate(max_body);
        }
        let mut req_body = ex.request.body.clone();
        req_body.truncate(max_body);
        self.conn.execute(
            "INSERT INTO entries (ts, file, env, vars, file_sha256, redacted, method, url, request_headers, request_body,
               status, http_version, reason, response_headers, response_body, body_truncated, timing, total_ms, curl_exit, error, response_size)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
            params![
                Utc::now().to_rfc3339(),
                meta.file,
                meta.env,
                serde_json::to_string(&meta.vars)?,
                meta.file_sha256,
                meta.redacted,
                ex.request.method,
                ex.request.url,
                serde_json::to_string(&ex.request.headers)?,
                req_body,
                resp.map(|r| r.status),
                resp.map(|r| r.http_version.clone()),
                resp.map(|r| r.reason.clone()),
                resp.map(|r| serde_json::to_string(&r.headers)).transpose()?,
                body,
                truncated,
                serde_json::to_string(&ex.timing)?,
                ex.timing.total_ms,
                ex.curl_exit,
                ex.error,
                resp.map(|r| r.size.max(r.body.len()) as i64),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    fn from_row(row: &Row<'_>) -> rusqlite::Result<Entry> {
        let json = |i: usize| -> rusqlite::Result<String> { row.get(i) };
        let parse_err = |e: serde_json::Error| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        };
        let ts: String = row.get(1)?;
        let status: Option<u16> = row.get(11)?;
        let request_body: Vec<u8> = row.get(10)?;
        let response = match status {
            Some(status) => Some(ResponseRecord {
                status,
                http_version: row.get::<_, Option<String>>(12)?.unwrap_or_default(),
                reason: row.get::<_, Option<String>>(13)?.unwrap_or_default(),
                headers: serde_json::from_str(
                    &row.get::<_, Option<String>>(14)?
                        .unwrap_or_else(|| "[]".into()),
                )
                .map_err(parse_err)?,
                size: row.get::<_, Option<i64>>(21)?.unwrap_or_default() as usize,
                body: row.get::<_, Option<Vec<u8>>>(15)?.unwrap_or_default(),
            }),
            None => None,
        };
        let response_body = response
            .as_ref()
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .unwrap_or_default();
        let exchange = Exchange {
            request: RequestRecord {
                method: row.get(7)?,
                url: row.get(8)?,
                headers: serde_json::from_str(&json(9)?).map_err(parse_err)?,
                body: request_body.clone(),
            },
            response,
            timing: serde_json::from_str::<Timing>(&json(17)?).map_err(parse_err)?,
            curl_exit: row.get(19)?,
            error: row.get(20)?,
        };
        Ok(Entry {
            id: row.get(0)?,
            ts: DateTime::parse_from_rfc3339(&ts)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_default(),
            file: row.get(2)?,
            env: row.get(3)?,
            vars: serde_json::from_str(&json(4)?).map_err(parse_err)?,
            file_sha256: row.get(5)?,
            redacted: row.get(6)?,
            body_truncated: row.get(16)?,
            request_body: String::from_utf8_lossy(&request_body).into_owned(),
            response_body,
            exchange,
        })
    }

    /// Fetches one entry.
    pub fn get(&self, id: i64) -> Result<Entry> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM entries WHERE id = ?1"),
                [id],
                History::from_row,
            )
            .optional()?
            .with_context(|| format!("no history entry #{id}"))
    }

    /// Lists entries matching `q`, newest first.
    pub fn search(&self, q: &Query) -> Result<Vec<Entry>> {
        let mut sql = format!("SELECT {COLUMNS} FROM entries WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(t) = &q.text {
            let like = format!(
                "%{}%",
                t.replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            );
            sql.push_str(" AND (url LIKE ? ESCAPE '\\' OR file LIKE ? ESCAPE '\\' OR CAST(response_body AS TEXT) LIKE ? ESCAPE '\\')");
            args.extend([
                Box::new(like.clone()) as Box<dyn rusqlite::ToSql>,
                Box::new(like.clone()),
                Box::new(like),
            ]);
        }
        if let Some(s) = &q.status {
            if let Some(class) = s.strip_suffix("xx").and_then(|c| c.parse::<u16>().ok()) {
                sql.push_str(" AND status >= ? AND status < ?");
                args.extend([
                    Box::new(class * 100) as Box<dyn rusqlite::ToSql>,
                    Box::new(class * 100 + 100),
                ]);
            } else {
                let code: u16 = s
                    .parse()
                    .with_context(|| format!("invalid status filter `{s}` (use 404 or 4xx)"))?;
                sql.push_str(" AND status = ?");
                args.push(Box::new(code));
            }
        }
        if let Some(m) = &q.method {
            sql.push_str(" AND method = ?");
            args.push(Box::new(m.to_ascii_uppercase()));
        }
        if let Some(f) = &q.file {
            sql.push_str(" AND file LIKE ?");
            args.push(Box::new(format!("%{f}%")));
        }
        if let Some(e) = &q.env {
            sql.push_str(" AND env = ?");
            args.push(Box::new(e.clone()));
        }
        if let Some(since) = &q.since {
            sql.push_str(" AND ts >= ?");
            args.push(Box::new(since.to_rfc3339()));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        args.push(Box::new(if q.limit == 0 { 20 } else { q.limit } as i64));
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(args.iter().map(|a| a.as_ref())),
            History::from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Deletes entries; `keep` retains the newest N. Returns rows deleted.
    pub fn prune(&self, keep: Option<usize>, older_than: Option<DateTime<Utc>>) -> Result<usize> {
        let mut n = 0;
        if let Some(keep) = keep {
            n += self.conn.execute("DELETE FROM entries WHERE id NOT IN (SELECT id FROM entries ORDER BY id DESC LIMIT ?1)", [keep as i64])?;
        }
        if let Some(t) = older_than {
            n += self
                .conn
                .execute("DELETE FROM entries WHERE ts < ?1", [t.to_rfc3339()])?;
        }
        if keep.is_none() && older_than.is_none() {
            bail!("prune needs --keep, --older-than, or --all");
        }
        Ok(n)
    }

    /// Deletes every entry.
    pub fn clear(&self) -> Result<usize> {
        Ok(self.conn.execute("DELETE FROM entries", [])?)
    }
}

const COLUMNS: &str = "id, ts, file, env, vars, file_sha256, redacted, method, url, request_headers, request_body,
  status, http_version, reason, response_headers, response_body, body_truncated, timing, total_ms, curl_exit, error, response_size";

/// Sorts object keys recursively so diffs ignore key order.
fn sort_json(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                m.into_iter().map(|(k, v)| (k, sort_json(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.into_iter().map(sort_json).collect())
        }
        other => other,
    }
}

/// Text form of an entry's response used for diffing.
pub fn diff_text(e: &Entry, ignore_headers: &[String]) -> String {
    let Some(r) = &e.exchange.response else {
        return format!(
            "curl error (exit {}): {}\n",
            e.exchange.curl_exit,
            e.exchange.error.clone().unwrap_or_default()
        );
    };
    let mut out = format!("{} {} {}\n", r.http_version, r.status, r.reason).replace("  \n", "\n");
    let mut headers: Vec<_> = r
        .headers
        .iter()
        .filter(|(k, _)| !ignore_headers.iter().any(|i| i.eq_ignore_ascii_case(k)))
        .collect();
    headers.sort_by_key(|(k, _)| k.to_ascii_lowercase());
    for (k, v) in headers {
        out.push_str(&format!("{}: {v}\n", k.to_ascii_lowercase()));
    }
    out.push('\n');
    let kind = body_kind(r.content_type(), &r.body);
    let body = match serde_json::from_slice::<serde_json::Value>(&r.body) {
        Ok(v) => serde_json::to_string_pretty(&sort_json(v)).unwrap_or_default(),
        Err(_) => pretty_body(kind, &r.body),
    };
    out.push_str(&body);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Unified diff of two entries' responses; empty when identical.
pub fn diff(a: &Entry, b: &Entry, ignore_headers: &[String], color: bool) -> String {
    let (ta, tb) = (diff_text(a, ignore_headers), diff_text(b, ignore_headers));
    if ta == tb {
        return String::new();
    }
    let p = Paint { on: color };
    let text = TextDiff::from_lines(&ta, &tb)
        .unified_diff()
        .context_radius(3)
        .header(&format!("#{}", a.id), &format!("#{}", b.id))
        .to_string();
    text.lines()
        .map(|l| {
            if l.starts_with("+++") || l.starts_with("---") {
                p.bold(l)
            } else if l.starts_with('+') {
                p.green(l)
            } else if l.starts_with('-') {
                p.red(l)
            } else if l.starts_with("@@") {
                p.cyan(l)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(status: u16, body: &str) -> Exchange {
        Exchange {
            request: RequestRecord {
                method: "GET".into(),
                url: format!("http://h/{status}"),
                headers: vec![],
                body: vec![],
            },
            response: Some(ResponseRecord {
                status,
                http_version: "HTTP/1.1".into(),
                reason: "OK".into(),
                headers: vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("Date".into(), status.to_string()),
                ],
                size: body.len(),
                body: body.as_bytes().to_vec(),
            }),
            timing: Timing {
                total_ms: 5.0,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn insert_get_search_prune() {
        let tmp = tempfile::tempdir().unwrap();
        let h = History::open(&tmp.path().join("h.db")).unwrap();
        let meta = NewEntry {
            file: Some("users/get.curl".into()),
            env: Some("local".into()),
            redacted: true,
            ..Default::default()
        };
        let a = h
            .insert(&meta, &ex(200, r#"{"name":"ada"}"#), 1024)
            .unwrap();
        let b = h
            .insert(
                &NewEntry {
                    file: Some("other.curl".into()),
                    ..meta.clone()
                },
                &ex(404, r#"{"error":"nope"}"#),
                1024,
            )
            .unwrap();
        let e = h.get(a).unwrap();
        assert_eq!(e.exchange.response.as_ref().unwrap().status, 200);
        assert_eq!(e.response_body, r#"{"name":"ada"}"#);
        assert_eq!(
            h.search(&Query {
                text: Some("ada".into()),
                ..Default::default()
            })
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            h.search(&Query {
                status: Some("4xx".into()),
                ..Default::default()
            })
            .unwrap()[0]
                .id,
            b
        );
        assert_eq!(
            h.search(&Query {
                file: Some("users".into()),
                ..Default::default()
            })
            .unwrap()[0]
                .id,
            a
        );
        assert_eq!(
            h.search(&Query {
                text: Some("%".into()),
                ..Default::default()
            })
            .unwrap()
            .len(),
            0,
            "LIKE wildcards are escaped"
        );
        assert!(
            h.search(&Query {
                status: Some("abc".into()),
                ..Default::default()
            })
            .is_err()
        );
        assert_eq!(
            h.search(&Query::default()).unwrap()[0].id,
            b,
            "newest first"
        );
        assert_eq!(h.prune(Some(1), None).unwrap(), 1);
        assert!(h.get(a).is_err());
    }

    #[test]
    fn truncates_large_bodies() {
        let tmp = tempfile::tempdir().unwrap();
        let h = History::open(&tmp.path().join("h.db")).unwrap();
        let id = h
            .insert(&NewEntry::default(), &ex(200, "0123456789"), 4)
            .unwrap();
        let e = h.get(id).unwrap();
        assert!(e.body_truncated);
        assert_eq!(e.response_body, "0123");
    }

    #[test]
    fn diff_ignores_key_order_and_selected_headers() {
        let tmp = tempfile::tempdir().unwrap();
        let h = History::open(&tmp.path().join("h.db")).unwrap();
        let a = h
            .get(
                h.insert(&NewEntry::default(), &ex(200, r#"{"a":1,"b":2}"#), 1024)
                    .unwrap(),
            )
            .unwrap();
        let b = h
            .get(
                h.insert(&NewEntry::default(), &ex(200, r#"{"b":2,"a":1}"#), 1024)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(diff(&a, &b, &["date".into()], false), "");
        let c = h
            .get(
                h.insert(&NewEntry::default(), &ex(200, r#"{"a":1,"b":3}"#), 1024)
                    .unwrap(),
            )
            .unwrap();
        let d = diff(&a, &c, &["date".into()], false);
        assert!(
            d.contains("-  \"b\": 2") && d.contains("+  \"b\": 3"),
            "{d}"
        );
    }
}
