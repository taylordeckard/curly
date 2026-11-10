//! End-to-end tests for `curly run`, the viewer flags, history, secrets, lint, and redaction.

mod common;

use common::{DEMO_PASSWORD, Fixture, stderr, stdout};

#[test]
fn run_prints_formatted_response_and_records_history() {
    let fx = Fixture::new();
    let out = fx.curly(&["run", "users/get-user.curl"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(s.starts_with("HTTP/1.1 200 OK  "), "{s}");
    assert!(s.contains("content-type: application/json"));
    assert!(
        s.contains("{\n  \"id\": 1,\n  \"name\": \"Ada Lovelace\""),
        "{s}"
    );
    assert!(!s.contains('\x1b'), "no colors when not a terminal");
    assert!(stderr(&out).contains("history #1"));
    assert!(fx.root().join(".curly/.gitignore").is_file());
}

#[test]
fn view_flags() {
    let fx = Fixture::new();
    let raw = fx.curly(&["run", "users/get-user.curl", "--raw"]);
    assert_eq!(
        stdout(&raw),
        r#"{"id":1,"name":"Ada Lovelace","email":"ada@example.test"}"#
    );
    let short = fx.curly(&["run", "users/get-user.curl", "-r"]);
    assert_eq!(stdout(&short), stdout(&raw), "-r is short for --raw");
    let headers = stdout(&fx.curly(&["run", "users/get-user.curl", "--headers"]));
    assert!(headers.contains("content-type") && !headers.contains("Ada"));
    let body = stdout(&fx.curly(&["run", "users/get-user.curl", "--body"]));
    assert!(body.starts_with('{') && !body.contains("HTTP/1.1"));
    let jq = stdout(&fx.curly(&["run", "users/list-users.curl", "--jq", "[.items[].name]"]));
    assert_eq!(jq, "[\n  \"Ada Lovelace\",\n  \"Alan Turing\"\n]\n");
    let jp = stdout(&fx.curly(&[
        "run",
        "users/list-users.curl",
        "--path",
        "$.items[?@.id == 2].email",
    ]));
    assert_eq!(jp, "\"alan@example.test\"\n");
    let xml = stdout(&fx.curly(&["run", "formats/xml.curl", "--body"]));
    assert!(xml.contains("<catalog>\n  <book id=\"1\">"), "{xml}");
    let verbose = stdout(&fx.curly(&["run", "misc/echo.curl", "-v", "--plain"]));
    assert!(
        verbose.contains("> PUT ")
            && verbose.contains("> X-Client: curly-examples")
            && verbose.contains("line one\nline two"),
        "{verbose}"
    );
    let conflict = fx.curly(&["run", "users/get-user.curl", "--raw", "--body"]);
    assert_eq!(conflict.status.code(), Some(2));
}

#[test]
fn var_overrides_and_environment_listing() {
    let fx = Fixture::new();
    let s = stdout(&fx.curly(&["run", "users/get-user.curl", "--var", "user_id=2", "--body"]));
    assert!(s.contains("Alan Turing"));
    let envs = stdout(&fx.curly(&["env", "list"]));
    assert!(
        envs.starts_with("local (default)\tenvs/local.curl"),
        "{envs}"
    );
    let vars = stdout(&fx.curly(&["env", "vars"]));
    assert!(
        vars.contains("DEMO_PASSWORD = [REDACTED]") && vars.contains("user_id = 1"),
        "{vars}"
    );
    assert!(!vars.contains(DEMO_PASSWORD));
}

#[test]
fn redaction_keeps_secrets_out_of_output_and_history() {
    let fx = Fixture::new();
    let out = fx.curly(&["run", "auth/login.curl", "-v"]);
    let s = stdout(&out);
    assert!(
        s.contains("\"access_token\": \"[REDACTED]\"") && s.contains("\"token_type\": \"Bearer\""),
        "{s}"
    );
    assert!(
        s.contains("\"password\": \"[REDACTED]\"") && !s.contains(DEMO_PASSWORD),
        "{s}"
    );

    let token = fx.login_token();
    assert_eq!(token.len(), 64);
    let set = fx.curly_stdin(&["secret", "set", "API_TOKEN"], &format!("{token}\n"));
    assert!(set.status.success(), "{}", stderr(&set));
    assert_eq!(stdout(&fx.curly(&["secret", "list"])), "local\tAPI_TOKEN\n");

    let me = fx.curly(&["run", "auth/me.curl", "-v"]);
    let s = stdout(&me);
    assert!(
        s.contains("HTTP/1.1 200 OK") && s.contains("> Authorization: Bearer [REDACTED]"),
        "{s}"
    );
    let shown = stdout(&fx.curly(&["run", "auth/me.curl", "-v", "--show-secrets"]));
    assert!(
        shown.contains(&token),
        "--show-secrets reveals the token in output"
    );

    let db = std::fs::read(fx.root().join(".curly/history.db")).unwrap();
    let db = String::from_utf8_lossy(&db);
    assert!(!db.contains(&token), "token must never reach history");
    assert!(
        !db.contains(DEMO_PASSWORD),
        "password must never reach history"
    );

    let hist = stdout(&fx.curly(&["history", "show", "last", "-v"]));
    assert!(hist.contains("Bearer [REDACTED]"), "{hist}");
}

#[test]
fn secret_cli_vars_are_not_stored_and_rerun_asks_for_them() {
    let fx = Fixture::new();
    let token = fx.login_token();
    let out = fx.curly(&[
        "run",
        "auth/me.curl",
        "--var",
        &format!("API_TOKEN={token}"),
    ]);
    assert!(stdout(&out).contains("200 OK"), "{}", stdout(&out));
    let db = String::from_utf8_lossy(&std::fs::read(fx.root().join(".curly/history.db")).unwrap())
        .into_owned();
    assert!(!db.contains(&token));
    let rerun = fx.curly(&["history", "rerun", "last"]);
    assert_eq!(rerun.status.code(), Some(2));
    assert!(
        stderr(&rerun).contains("pass it again with --var API_TOKEN="),
        "{}",
        stderr(&rerun)
    );
    let rerun = fx.curly(&[
        "history",
        "rerun",
        "last",
        "--var",
        &format!("API_TOKEN={token}"),
    ]);
    assert!(stdout(&rerun).contains("200 OK"), "{}", stderr(&rerun));
}

#[test]
fn history_list_search_show_diff_rerun_prune() {
    let fx = Fixture::new();
    fx.curly(&["run", "users/get-user.curl"]);
    fx.curly(&["run", "users/get-missing-user.curl"]);
    fx.curly(&["run", "users/get-user.curl", "--var", "user_id=2"]);

    let list = stdout(&fx.curly(&["history", "list"]));
    let lines: Vec<&str> = list.lines().collect();
    assert_eq!(lines.len(), 3, "{list}");
    assert!(
        lines[0].trim_start().starts_with("#3") && lines[1].contains("404"),
        "{list}"
    );

    let found = stdout(&fx.curly(&["history", "search", "Turing"]));
    assert!(found.contains("#3") && !found.contains("#1 "), "{found}");
    let found = stdout(&fx.curly(&["history", "search", "users", "--status", "4xx"]));
    assert_eq!(found.lines().count(), 1);
    let json: serde_json::Value = serde_json::from_str(&stdout(
        &fx.curly(&["history", "list", "--json", "-n", "1"]),
    ))
    .unwrap();
    assert_eq!(json[0]["id"], 3);
    assert_eq!(json[0]["vars"]["user_id"], "2");

    let show = stdout(&fx.curly(&["history", "show", "1"]));
    assert!(
        show.starts_with("#1  ")
            && show.contains("users/get-user.curl")
            && show.contains("Ada Lovelace"),
        "{show}"
    );
    assert!(stdout(&fx.curly(&["history", "show", "1", "--jq", ".name"])).contains("Ada Lovelace"));

    let diff = fx.curly(&["history", "diff", "1", "3"]);
    assert_eq!(diff.status.code(), Some(1), "differences exit 1");
    let d = stdout(&diff);
    assert!(
        d.contains("-  \"name\": \"Ada Lovelace\"") && d.contains("+  \"name\": \"Alan Turing\""),
        "{d}"
    );
    assert!(!d.contains("date:"), "date is ignored by default");

    let rerun = fx.curly(&["history", "rerun", "3", "--body"]);
    assert!(
        stdout(&rerun).contains("Alan Turing"),
        "re-run keeps --var user_id=2"
    );
    assert!(stderr(&rerun).contains("re-run of #3"));
    let same = stdout(&fx.curly(&["history", "diff", "3", "4"]));
    assert!(same.contains("identical"), "{same}");

    let pruned = stdout(&fx.curly(&["history", "prune", "--keep", "1"]));
    assert_eq!(pruned.trim(), "deleted 3 entries");
    assert_eq!(stdout(&fx.curly(&["history", "list"])).lines().count(), 1);
}

#[test]
fn no_history_flag_and_transport_errors() {
    let fx = Fixture::new();
    fx.curly(&["run", "health.curl", "--no-history"]);
    assert_eq!(stdout(&fx.curly(&["history", "list"])), "");
    let out = fx.curly(&["run", "health.curl", "--var", "BASE_URL=http://127.0.0.1:9"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stderr(&out).contains("curl error (exit 7)"),
        "{}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "", "errors go to stderr so pipes stay clean");
    assert!(
        stdout(&fx.curly(&["history", "list"])).contains("ERR"),
        "failed transfers are recorded"
    );
}

#[test]
fn undefined_variables_are_rejected_before_running() {
    let fx = Fixture::new();
    std::fs::write(
        fx.root().join("bad.curl"),
        "expand-url = \"{{BASE_URL}}/users/{{nope}}\"\n",
    )
    .unwrap();
    let out = fx.curly(&["run", "bad.curl"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("`{{nope}}` is not defined in environment `local`"),
        "{}",
        stderr(&out)
    );
}

/// An environment can rename a shell variable with `--expand-variable`; curly
/// resolves it like curl and still treats the copied value as a secret.
#[test]
fn expand_variable_maps_a_shell_secret_to_another_name() {
    let fx = Fixture::new();
    let token = fx.login_token();
    let env = fx.root().join("envs/local.curl");
    let mut text = std::fs::read_to_string(&env).unwrap();
    text.push_str("--variable %MY_SHELL_KEY=\n--expand-variable API_TOKEN={{MY_SHELL_KEY}}\n");
    std::fs::write(&env, text).unwrap();
    let shell = [("MY_SHELL_KEY", token.as_str())];

    let lint = fx.curly_env(&["lint", "auth/me.curl"], &shell);
    assert!(lint.status.success(), "{}", stdout(&lint));
    let me = fx.curly_env(&["run", "auth/me.curl", "-v"], &shell);
    let s = stdout(&me);
    assert!(
        s.contains("HTTP/1.1 200 OK") && s.contains("> Authorization: Bearer [REDACTED]"),
        "{s}"
    );
    assert!(!s.contains(&token), "copied secret must stay redacted");
    let db = std::fs::read(fx.root().join(".curly/history.db")).unwrap();
    assert!(!String::from_utf8_lossy(&db).contains(&token));

    let out = fx.curl_env(
        &["-sS", "-o", "/dev/null", "-w", "%{http_code}", "-K", "envs/local.curl", "-K", "auth/me.curl"],
        &shell,
    );
    assert_eq!(stdout(&out), "200", "plain curl resolves the same mapping");
}

/// Lint must know stored secret names from the index alone: reading values
/// would open the OS keychain and can prompt for the login password.
#[test]
fn lint_uses_secret_names_without_reading_the_store() {
    let fx = Fixture::new();
    let set = fx.curly_stdin(&["secret", "set", "LINT_ONLY_TOKEN"], "value-1\n");
    assert!(set.status.success(), "{}", stderr(&set));
    std::fs::write(
        fx.root().join("uses-secret.curl"),
        "--expand-url {{BASE_URL}}/health\n--expand-header \"X-Token: {{LINT_ONLY_TOKEN}}\"\n",
    )
    .unwrap();
    let store = fx.dir.path().join("secrets.json");
    std::fs::remove_file(&store).unwrap();

    let out = fx.curly(&["lint", "uses-secret.curl"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("0 errors"), "{}", stdout(&out));
    assert!(!store.exists(), "lint must not touch the secret store");
}

#[test]
fn lint_passes_examples_and_flags_problems() {
    let fx = Fixture::new();
    let out = fx.curly(&["lint"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("0 errors"));
    std::fs::write(
        fx.root().join("bad.curl"),
        "url = a\nurl = b\nbogus-option = 1\nheader = \"Authorization: Bearer abc\"\n",
    )
    .unwrap();
    let out = fx.curly(&["lint", "bad.curl"]);
    assert_eq!(out.status.code(), Some(1));
    let s = stdout(&out);
    assert!(s.contains("unknown curl option `bogus-option`"), "{s}");
    assert!(
        s.contains("exactly one request") && s.contains("hardcoded credential"),
        "{s}"
    );
}

#[test]
fn init_creates_a_runnable_collection() {
    let tmp = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_curly"))
        .args(["init", "--name", "fresh"])
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).contains("created"));
    let lint = std::process::Command::new(env!("CARGO_BIN_EXE_curly"))
        .arg("lint")
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert!(lint.status.success(), "{}", stdout(&lint));
    let gi = std::fs::read_to_string(tmp.path().join("envs/.gitignore")).unwrap();
    assert_eq!(gi, "*.secrets.curl\n");
}
