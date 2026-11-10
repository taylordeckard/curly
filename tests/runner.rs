//! End-to-end tests for assertions, captures, folder inheritance, the
//! collection runner, data-driven runs, hooks, and reports.

mod common;

use std::fs;

use common::{Fixture, stderr, stdout};

#[test]
fn whole_collection_passes_with_reports() {
    let fx = Fixture::new();
    assert!(fx.browser_login("oauth/browser").status.success());
    let out = fx.curly(&[
        "run",
        ".",
        "--report",
        "junit=out/junit.xml",
        "--report",
        "json=out/report.json",
    ]);
    let s = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{s}\n{}", stderr(&out));
    let order: Vec<&str> = s
        .lines()
        .filter(|l| l.starts_with('✓'))
        .map(|l| l.split_whitespace().nth(1).unwrap())
        .collect();
    assert_eq!(
        order,
        vec![
            "health.curl",
            "auth/login.curl",
            "auth/me.curl",
            "users/create-user.curl",
            "users/get-created-user.curl",
            "users/list-users.curl",
            "users/get-user.curl",
            "users/get-missing-user.curl",
            "formats/html.curl",
            "formats/text.curl",
            "formats/xml.curl",
            "misc/echo.curl",
            "misc/slow.curl",
            "imported/meta/get-health.curl",
            "imported/users/list-users.curl",
            "imported/users/create-user.curl",
            "imported/users/get-user.curl",
            "imported/users/delete-user.curl",
            "imported/auth/login.curl",
            "imported/auth/get-current-user.curl",
            "oauth/service-me.curl",
            "oauth/browser/me.curl",
            "graphql/create-user.curl",
            "graphql/get-user.curl",
            "graphql/me.curl",
            "graphql/ping.curl",
            "ws/echo.ws",
            "ws/chat.ws",
            "grpc/get-user.grpc",
            "grpc/get-missing-user.grpc",
            "grpc/list-users.grpc",
            "grpc/create-users.grpc",
            "grpc/shout.grpc",
            "grpc/whoami.grpc"
        ],
        "runs in _folder.toml order"
    );
    assert!(s.contains("34 requests: 34 passed"), "{s}");

    let xml = fs::read_to_string(fx.root().join("out/junit.xml")).unwrap();
    assert!(
        xml.contains("<testsuites name=\"curly\" tests=\"34\" failures=\"0\" errors=\"0\""),
        "{xml}"
    );
    let mut reader = quick_xml::Reader::from_str(&xml);
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(e) => panic!("invalid JUnit XML: {e}"),
        }
    }
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(fx.root().join("out/report.json")).unwrap())
            .unwrap();
    assert_eq!(json["summary"]["passed"], 34);
    assert_eq!(json["results"][1]["captured"][0], "API_TOKEN");
    assert!(
        json["results"][1].get("exchange").is_none(),
        "reports never include bodies"
    );
}

#[test]
fn captured_token_is_used_but_never_reported_or_stored() {
    let fx = Fixture::new();
    let out = fx.curly(&[
        "run",
        "auth",
        "--report",
        "json=r.json",
        "--report",
        "junit=r.xml",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let token = fx.login_token();
    for f in ["r.json", "r.xml"] {
        let text = fs::read_to_string(fx.root().join(f)).unwrap();
        assert!(
            !text.contains(&token[..16]),
            "{f} must not contain token material"
        );
    }
    let alone = fx.curly(&["run", "auth/me.curl"]);
    assert_eq!(
        alone.status.code(),
        Some(1),
        "without the capture the token is empty"
    );
    assert!(
        stderr(&alone).contains("✗ status is 200: got 401"),
        "{}",
        stderr(&alone)
    );
    let db = String::from_utf8_lossy(&fs::read(fx.root().join(".curly/history.db")).unwrap())
        .into_owned();
    assert!(!db.contains(&token));
}

#[test]
fn failures_explain_and_set_exit_code() {
    let fx = Fixture::new();
    let out = fx.curly(&[
        "run",
        "users/get-user.curl",
        "users/get-missing-user.curl",
        "--var",
        "expected_name=Bob",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let s = stdout(&out);
    assert!(s.contains("✗ users/get-user.curl  200"), "{s}");
    assert!(
        s.contains("    ✗ $.name eq \"Bob\": got \"Ada Lovelace\""),
        "{s}"
    );
    assert!(s.contains("✓ users/get-missing-user.curl  404"), "{s}");
    assert!(s.contains("2 requests: 1 passed, 1 failed"), "{s}");
}

#[test]
fn bail_skips_the_rest() {
    let fx = Fixture::new();
    let out = fx.curly(&[
        "run",
        "users",
        "--var",
        "created_id=999",
        "--bail",
        "--report",
        "junit=j.xml",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let s = stdout(&out);
    assert!(
        s.contains("5 requests: 1 passed, 1 failed, 3 skipped"),
        "{s}"
    );
    assert_eq!(
        fs::read_to_string(fx.root().join("j.xml"))
            .unwrap()
            .matches("<skipped/>")
            .count(),
        3
    );
    let cont = fx.curly(&["run", "users", "--var", "created_id=999"]);
    assert!(
        stdout(&cont).contains("5 requests: 4 passed, 1 failed"),
        "{}",
        stdout(&cont)
    );
}

#[test]
fn data_driven_runs_from_csv_json_and_folder_default() {
    let fx = Fixture::new();
    let out = fx.curly(&["run", "users/get-user.curl", "--data", "data/users.csv"]);
    let s = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{s}");
    assert!(
        s.contains("✓ [1] users/get-user.curl") && s.contains("✓ [2] users/get-user.curl"),
        "{s}"
    );
    assert!(
        s.contains("2 requests across 2 iterations: 2 passed"),
        "{s}"
    );

    fs::write(fx.root().join("rows.json"), r#"[{"user_id": 2, "expected_name": "Alan Turing"}, {"user_id": 1, "expected_name": "Wrong"}]"#).unwrap();
    let out = fx.curly(&[
        "run",
        "users/get-user.curl",
        "--data",
        "rows.json",
        "--report",
        "junit=d.xml",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout(&out).contains("✗ [2] users/get-user.curl"),
        "{}",
        stdout(&out)
    );
    let xml = fs::read_to_string(fx.root().join("d.xml")).unwrap();
    assert!(
        xml.contains("name=\"curly iteration 1\"") && xml.contains("name=\"curly iteration 2\""),
        "{xml}"
    );

    let dir = fx.root().join("lookups");
    fs::create_dir_all(&dir).unwrap();
    fs::copy(
        fx.root().join("users/get-user.curl"),
        dir.join("get-user.curl"),
    )
    .unwrap();
    fs::copy(
        fx.root().join("users/get-user.test.toml"),
        dir.join("get-user.test.toml"),
    )
    .unwrap();
    fs::write(dir.join("_folder.toml"), "data = \"data/users.csv\"\n").unwrap();
    let out = fx.curly(&["run", "lookups"]);
    assert!(
        stdout(&out).contains("2 requests across 2 iterations: 2 passed"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn folder_vars_inherit_with_nearer_winning_and_env_overriding() {
    let fx = Fixture::new();
    let vars = stdout(&fx.curly(&["env", "vars", "users/get-user.curl"]));
    assert!(
        vars.contains("expected_name = Ada Lovelace\t# users/_folder.toml"),
        "{vars}"
    );
    fs::write(fx.root().join("_folder.toml"), "order = [\"health.curl\", \"auth/\", \"users/\"]\n[vars]\nexpected_name = \"root\"\nuser_id = \"42\"\nonly_root = \"r\"\n").unwrap();
    let vars = stdout(&fx.curly(&["env", "vars", "users/get-user.curl"]));
    assert!(
        vars.contains("expected_name = Ada Lovelace\t# users/_folder.toml"),
        "nearer folder wins: {vars}"
    );
    assert!(vars.contains("only_root = r\t# _folder.toml"), "{vars}");
    assert!(
        vars.contains("user_id = 1\t# envs/local.curl"),
        "environment beats folder defaults: {vars}"
    );
    let cmd = stdout(&fx.curly(&["cmd", "users/get-user.curl"]));
    assert!(
        cmd.contains("--variable 'expected_name=Ada Lovelace'"),
        "{cmd}"
    );
}

#[test]
fn hooks_can_fail_a_request() {
    let fx = Fixture::new();
    let ok = fx.curly(&["run", "misc/echo.curl", "--body"]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
    assert!(
        stderr(&ok).contains("✓ server saw X-Client")
            && stderr(&ok).contains("✓ hook scripts/check-echo.sh"),
        "{}",
        stderr(&ok)
    );
    let curl_file = fx.root().join("misc/echo.curl");
    let src = fs::read_to_string(&curl_file)
        .unwrap()
        .replace("X-Client: curly-examples", "X-Other: 1");
    fs::write(&curl_file, src).unwrap();
    let bad = fx.curly(&["run", "misc/echo.curl"]);
    assert_eq!(bad.status.code(), Some(1));
    assert!(
        stderr(&bad)
            .contains("✗ hook scripts/check-echo.sh: the echoed headers did not include X-Client"),
        "{}",
        stderr(&bad)
    );
}

#[test]
fn errors_are_classified() {
    let fx = Fixture::new();
    let transport = fx.curly(&[
        "run",
        "health.curl",
        "formats",
        "--var",
        "BASE_URL=http://127.0.0.1:9",
    ]);
    assert_eq!(transport.status.code(), Some(3));
    assert!(
        stdout(&transport).contains("! health.curl  ---"),
        "{}",
        stdout(&transport)
    );
    fs::write(
        fx.root().join("formats/text.test.toml"),
        "[expect]\nstatuss = 200\n",
    )
    .unwrap();
    let config = fx.curly(&["run", "formats"]);
    assert_eq!(config.status.code(), Some(2));
    assert!(
        stdout(&config).contains("unknown field `statuss`"),
        "{}",
        stdout(&config)
    );
}

#[test]
fn lint_checks_sidecars_and_folders() {
    let fx = Fixture::new();
    assert!(
        fx.curly(&["lint"]).status.success(),
        "{}",
        stdout(&fx.curly(&["lint"]))
    );
    fs::write(
        fx.root().join("formats/xml.test.toml"),
        "[capture]\nx = \"nonsense\"\n",
    )
    .unwrap();
    fs::write(
        fx.root().join("misc/_folder.toml"),
        "order = [\"gone.curl\"]\n[vars]\nAPI_TOKEN = \"literal\"\n",
    )
    .unwrap();
    let out = fx.curly(&["lint"]);
    assert_eq!(out.status.code(), Some(1));
    let s = stdout(&out);
    assert!(
        s.contains("formats/xml.test.toml:0: error: capture `x`: unknown capture source"),
        "{s}"
    );
    assert!(
        s.contains("misc/_folder.toml:0: error: misc/_folder.toml: order lists `gone.curl`"),
        "{s}"
    );
    assert!(
        s.contains("hardcoded credential `API_TOKEN` in [vars]"),
        "{s}"
    );
}
