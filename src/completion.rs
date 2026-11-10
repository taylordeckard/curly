//! Dynamic shell completion (bash, zsh, fish) via `clap_complete`.
//!
//! Shells call back into `curly` (`COMPLETE=<shell> curly -- <words>`), and the
//! functions here supply values: request files and folders, environments,
//! variable names, history ids, secret names, and report formats. Completion
//! never reads secret values: variable help shows values for non-secrets only,
//! and the secret store is never opened.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use clap_complete::engine::CompletionCandidate;

use crate::assertions::TestFile;
use crate::folder::{self, FOLDER_FILE};
use crate::history::Query;
use crate::project::{ENVS_DIR, Project, STATE_DIR};
use crate::secrets::SecretIndex;
use crate::vars::{Layers, VarContext, list_environments};

/// The collection containing the current directory, if any.
fn project() -> Option<Project> {
    Project::discover(Path::new(".")).ok()
}

fn candidate(value: impl Into<String>, help: impl Into<String>) -> CompletionCandidate {
    let help: String = help.into();
    CompletionCandidate::new(value.into()).help((!help.is_empty()).then(|| help.into()))
}

/// Splits `users/ge` into (`users/`, `ge`).
fn split_prefix(current: &str) -> (&str, &str) {
    match current.rfind('/') {
        Some(i) => (&current[..=i], &current[i + 1..]),
        None => ("", current),
    }
}

/// Whether `dir` contains a request file at any depth.
fn has_requests(dir: &Path) -> bool {
    crate::curlconf::find_requests(dir, dir).is_ok_and(|f| !f.is_empty())
}

/// Completes paths one segment at a time, keeping files that `keep` accepts
/// and folders that `keep_dir` accepts.
fn complete_paths(
    current: &OsStr,
    keep: &dyn Fn(&Path) -> Option<String>,
    keep_dir: &dyn Fn(&Path) -> bool,
) -> Vec<CompletionCandidate> {
    let current = current.to_string_lossy();
    let (dir, base) = split_prefix(&current);
    let search = if dir.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(dir)
    };
    let Ok(entries) = std::fs::read_dir(&search) else {
        return vec![];
    };
    let envs = project().map(|p| p.root.join(ENVS_DIR));
    let mut out: Vec<CompletionCandidate> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(base)
            || name.starts_with('.')
            || name.starts_with('_')
            || name == STATE_DIR
        {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            if envs.as_ref().is_some_and(|e| {
                std::fs::canonicalize(&path).ok().as_ref() == std::fs::canonicalize(e).ok().as_ref()
            }) || !keep_dir(&path)
            {
                continue;
            }
            out.push(candidate(format!("{dir}{name}/"), "folder"));
        } else if let Some(help) = keep(&path) {
            out.push(candidate(format!("{dir}{name}"), help));
        }
    }
    out.sort_by(|a, b| a.get_value().cmp(b.get_value()));
    out
}

/// Request files (with their `@name`) and folders.
pub fn requests(current: &OsStr) -> Vec<CompletionCandidate> {
    complete_paths(
        current,
        &|p| {
            p.file_name()
                .is_some_and(|n| crate::curlconf::is_request_name(&n.to_string_lossy()))
                .then(|| {
                    crate::curlconf::parse_file(p)
                        .ok()
                        .and_then(|c| c.meta.name)
                        .unwrap_or_default()
                })
        },
        &has_requests,
    )
}

/// Files with one of `exts`, labeled `label`.
fn files_with(current: &OsStr, exts: &[&str], label: &str) -> Vec<CompletionCandidate> {
    complete_paths(
        current,
        &|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .filter(|e| exts.contains(&e.to_ascii_lowercase().as_str()))
                .map(|_| label.to_string())
        },
        &|_| true,
    )
}

/// The project's `.curly/<name>` if it already exists (completion never creates state).
fn existing_state(p: &Project, name: &str) -> Option<PathBuf> {
    Some(p.root.join(STATE_DIR).join(name)).filter(|f| f.is_file())
}

/// CSV and JSON data files.
pub fn data_files(current: &OsStr) -> Vec<CompletionCandidate> {
    files_with(current, &["csv", "json"], "data file")
}

/// OpenAPI / Swagger documents.
pub fn spec_files(current: &OsStr) -> Vec<CompletionCandidate> {
    files_with(current, &["yaml", "yml", "json"], "API description")
}

/// Environment names.
pub fn environments() -> Vec<CompletionCandidate> {
    let Some(p) = project() else { return vec![] };
    let default = p.config.project.default_env.clone();
    list_environments(&p)
        .unwrap_or_default()
        .into_iter()
        .map(|e| {
            let mark = if Some(&e.name) == default.as_ref() {
                " (default)"
            } else {
                ""
            };
            candidate(e.name.clone(), format!("{}{mark}", e.file.display()))
        })
        .collect()
}

/// Every `_folder.toml` directory in the collection (collection-relative).
fn folder_dirs(root: &Path, rel: &Path, out: &mut Vec<PathBuf>) {
    if root.join(rel).join(FOLDER_FILE).is_file() {
        out.push(rel.to_path_buf());
    }
    let Ok(entries) = std::fs::read_dir(root.join(rel)) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if e.path().is_dir() && !name.starts_with('.') && name != ENVS_DIR {
            folder_dirs(root, &rel.join(name), out);
        }
    }
}

/// `(name, help)` for every variable the collection defines or provides.
pub fn variable_names(p: &Project) -> Vec<(String, String)> {
    let mut dirs = Vec::new();
    folder_dirs(&p.root, Path::new(""), &mut dirs);
    let mut folder_vars = Vec::new();
    let mut provided: Vec<(String, String)> = Vec::new();
    for d in &dirs {
        if let Ok(Some(cfg)) = folder::load(&p.root.join(d)) {
            folder_vars.extend(folder::folder_vars(p, &d.join("_")).unwrap_or_default());
            if let Some(auth) = cfg.auth {
                provided.push((
                    auth.token_var,
                    format!("OAuth token from {}", d.join(FOLDER_FILE).display()),
                ));
            }
            if let Some(rows) = cfg
                .data
                .and_then(|f| crate::runner::load_data(&p.root.join(f)).ok())
            {
                provided.extend(
                    rows[0]
                        .iter()
                        .map(|(k, _)| (k.clone(), "data column".to_string())),
                );
            }
        }
    }
    for f in crate::curlconf::find_requests(&p.root, &p.root).unwrap_or_default() {
        let rel = f.strip_prefix(&p.root).unwrap_or(&f).to_path_buf();
        if let Ok(Some(t)) = TestFile::load_for(&p.root, &rel) {
            provided.extend(
                t.capture_names()
                    .into_iter()
                    .map(|n| (n, format!("captured by {}", rel.display()))),
            );
        }
    }
    let mut out: Vec<(String, String)> = Vec::new();
    if let Ok(ctx) = VarContext::build(
        p,
        None,
        &Layers {
            folder: folder_vars,
            ..Default::default()
        },
        None,
    ) {
        for (name, r) in ctx.effective(&p.root) {
            let help = if r.secret {
                format!("secret ({})", r.location)
            } else {
                format!("{} ({})", r.value.unwrap_or_default(), r.location)
            };
            out.push((name, help));
        }
    }
    if let Some(index) = existing_state(p, "secrets.json").and_then(|_| SecretIndex::load(p).ok()) {
        for names in index.envs.values() {
            out.extend(
                names
                    .iter()
                    .map(|n| (n.clone(), "secret (secret store)".to_string())),
            );
        }
    }
    out.extend(provided);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// `NAME=` completions for `--var`.
pub fn variables(current: &OsStr) -> Vec<CompletionCandidate> {
    let current = current.to_string_lossy();
    if current.contains('=') {
        return vec![];
    }
    let Some(p) = project() else { return vec![] };
    variable_names(&p)
        .into_iter()
        .filter(|(n, _)| n.starts_with(current.as_ref()))
        .map(|(n, help)| candidate(format!("{n}="), help))
        .collect()
}

/// Recent history ids plus `last`.
pub fn history_ids() -> Vec<CompletionCandidate> {
    let Some(db) = project().and_then(|p| existing_state(&p, "history.db")) else {
        return vec![];
    };
    let Ok(h) = crate::history::History::open(&db) else {
        return vec![];
    };
    let mut out = vec![candidate("last", "newest entry")];
    for e in h
        .search(&Query {
            limit: 30,
            ..Default::default()
        })
        .unwrap_or_default()
    {
        let status = e
            .exchange
            .response
            .as_ref()
            .map(|r| r.status.to_string())
            .unwrap_or_else(|| "ERR".into());
        let target = e
            .file
            .clone()
            .unwrap_or_else(|| e.exchange.request.url.clone());
        out.push(candidate(
            e.id.to_string(),
            format!("{} {status} {target}", e.exchange.request.method),
        ));
    }
    out
}

/// Names of stored secrets.
pub fn secret_names() -> Vec<CompletionCandidate> {
    let Some(p) = project() else { return vec![] };
    let Some(index) = existing_state(&p, "secrets.json").and_then(|_| SecretIndex::load(&p).ok())
    else {
        return vec![];
    };
    index
        .envs
        .iter()
        .flat_map(|(env, names)| {
            names
                .iter()
                .map(move |n| candidate(n.clone(), format!("env {env}")))
        })
        .collect()
}

/// Root fields (`Query.user`) from every cached GraphQL schema.
pub fn graphql_fields(current: &OsStr) -> Vec<CompletionCandidate> {
    let current = current.to_string_lossy();
    let Some(p) = project() else { return vec![] };
    let mut out = Vec::new();
    for cached in crate::graphql::cached_schemas(&p) {
        for key in ["queryType", "mutationType", "subscriptionType"] {
            let Some(root) = cached.schema[key]["name"].as_str() else {
                continue;
            };
            for f in crate::graphql::fields_of(&cached.schema, root) {
                let value = format!("{root}.{}", f.name);
                if value.starts_with(current.as_ref()) {
                    out.push(candidate(
                        value,
                        format!("{} {}", f.ty, f.description).trim().to_string(),
                    ));
                }
            }
        }
    }
    out.sort_by(|a, b| a.get_value().cmp(b.get_value()));
    out.dedup_by(|a, b| a.get_value() == b.get_value());
    out
}

/// `--report` formats.
pub fn reports(current: &OsStr) -> Vec<CompletionCandidate> {
    let current = current.to_string_lossy();
    if let Some((kind, path)) = current.split_once('=') {
        let ext = if kind == "junit" { "xml" } else { "json" };
        return complete_paths(
            OsStr::new(path),
            &|p| p.extension().is_some_and(|e| e == ext).then(String::new),
            &|_| true,
        )
        .into_iter()
        .map(|c| candidate(format!("{kind}={}", c.get_value().to_string_lossy()), ""))
        .collect();
    }
    vec![
        candidate("junit=", "JUnit XML report"),
        candidate("json=", "JSON report"),
    ]
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_prefixes() {
        assert_eq!(split_prefix("users/ge"), ("users/", "ge"));
        assert_eq!(split_prefix("ge"), ("", "ge"));
        assert_eq!(split_prefix("a/b/"), ("a/b/", ""));
    }

    #[test]
    fn report_candidates() {
        let values: Vec<String> = reports(OsStr::new(""))
            .iter()
            .map(|c| c.get_value().to_string_lossy().into_owned())
            .collect();
        assert_eq!(values, vec!["junit=", "json="]);
    }
}
