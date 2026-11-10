//! End-to-end tests for WebSocket requests: scripted steps, interactive mode,
//! auth, redaction, lint, and history.

mod common;

use std::fs;
use std::io::Write;
use std::process::Stdio;

use common::{Fixture, stderr, stdout};

#[test]
fn scripted_session_runs_steps_and_records_transcript() {
    let fx = Fixture::new();
    let out = fx.curly(&["run", "ws/echo.ws"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(s.starts_with("HTTP/1.1 101 Switching Protocols"), "{s}");
    assert!(
        s.contains("> {\"type\":\"join\",\"room\":\"lobby\"}"),
        "{s}"
    );
    assert!(
        s.lines().any(|l| l.starts_with("< ")
            && l.contains("\"type\":\"joined\"")
            && l.contains("\"room\":\"lobby\"")),
        "{s}"
    );
    let welcome = s.lines().find(|l| l.contains("welcome")).unwrap();
    let session = serde_json::from_str::<serde_json::Value>(&welcome[2..]).unwrap()["session"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        s.contains(&format!(
            "> {{\"type\":\"say\",\"text\":\"hello from {session}\"}}"
        )),
        "captured values feed later steps: {s}"
    );
    assert!(
        stderr(&out).contains("all 7 checks passed"),
        "{}",
        stderr(&out)
    );
    let hist = stdout(&fx.curly(&["history", "show", "last"]));
    assert!(
        hist.contains("ws/echo.ws")
            && hist
                .lines()
                .any(|l| l.starts_with("< ") && l.contains("\"type\":\"joined\"")),
        "{hist}"
    );
}

#[test]
fn failing_and_timed_out_steps_are_reported() {
    let fx = Fixture::new();
    fs::write(
        fx.root().join("ws/echo.test.toml"),
        "[[step]]\nreceive = 2000\n[[step.json]]\npath = \"$.type\"\neq = \"hello\"\n\n[[step]]\nreceive = 200\n",
    )
    .unwrap();
    let out = fx.curly(&["run", "ws/echo.ws"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(
        err.contains("✗ step 1: $.type eq \"hello\": got \"welcome\""),
        "{err}"
    );
    assert!(
        err.contains("✗ step 2: receive: no message within 200 ms"),
        "{err}"
    );

    fs::write(
        fx.root().join("ws/echo.test.toml"),
        "[[step]]\nsend = \"x\"\nreceive = 10\n",
    )
    .unwrap();
    let out = fx.curly(&["run", "ws/echo.ws"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out)
            .contains("step 1: needs exactly one of send, send_file, receive, sleep_ms, close"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn handshake_auth_uses_variables_and_captures() {
    let fx = Fixture::new();
    let denied = fx.curly(&["run", "ws/chat.ws"]);
    assert_eq!(denied.status.code(), Some(3));
    assert!(
        stderr(&denied)
            .contains("error: WebSocket handshake failed: HTTP 401 missing or invalid token"),
        "{}",
        stderr(&denied)
    );
    let token = fx.login_token();
    let ok = fx.curly(&["run", "ws/chat.ws", "--var", &format!("API_TOKEN={token}")]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
    let run = fx.curly(&["run", "auth/login.curl", "ws"]);
    assert!(
        stdout(&run).contains("3 requests: 3 passed"),
        "the token captured at login opens the chat: {}",
        stdout(&run)
    );
}

#[test]
fn secrets_in_messages_are_redacted() {
    let fx = Fixture::new();
    let token = fx.login_token();
    fs::write(
        fx.root().join("ws/leak.ws"),
        "expand-url = \"{{WS_URL}}/ws/echo\"\n",
    )
    .unwrap();
    fs::write(fx.root().join("ws/leak.test.toml"), "[[step]]\nreceive = 2000\n\n[[step]]\nsend = '{\"type\":\"say\",\"text\":\"{{API_TOKEN}}\"}'\n\n[[step]]\nreceive = 2000\n[[step.json]]\npath = \"$.text\"\neq = \"{{API_TOKEN}}\"\n").unwrap();
    let out = fx.curly(&["run", "ws/leak.ws", "--var", &format!("API_TOKEN={token}")]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let all = format!("{}{}", stdout(&out), stderr(&out));
    assert!(!all.contains(&token), "token must not be printed: {all}");
    assert!(all.contains("[REDACTED:API_TOKEN]"), "{all}");
    let db = String::from_utf8_lossy(&fs::read(fx.root().join(".curly/history.db")).unwrap())
        .into_owned();
    assert!(!db.contains(&token));
}

#[test]
fn binary_messages_and_interactive_mode() {
    let fx = Fixture::new();
    fs::write(fx.root().join("ws/blob.bin"), [0u8, 159, 146, 150, 255]).unwrap();
    fs::write(fx.root().join("ws/echo.test.toml"), "[[step]]\nreceive = 2000\n\n[[step]]\nsend_file = \"ws/blob.bin\"\n\n[[step]]\nreceive = 2000\n").unwrap();
    let out = fx.curly(&["run", "ws/echo.ws"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("> [binary, 5 bytes]\n< [binary, 5 bytes]"),
        "{}",
        stdout(&out)
    );

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_curly"))
        .args(["ws", "-i", "ws/echo.ws", "--plain"])
        .current_dir(fx.root())
        .env("WS_URL", fx.server.base_url().replace("http://", "ws://"))
        .env(
            "CURLY_SECRET_STORE",
            format!("file:{}", fx.dir.path().join("s.json").display()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"type\":\"say\",\"text\":\"typed\"}\nplain words\n/quit\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(
        s.contains("\"session\":")
            && s.lines()
                .any(|l| l.contains("\"text\":\"typed\"") && l.contains("\"type\":\"message\""))
            && s.contains("plain words"),
        "{s}"
    );
    assert!(
        stderr(&out).contains("connected to ws://"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn lint_and_cmd_know_about_ws_files() {
    let fx = Fixture::new();
    assert!(fx.curly(&["lint", "ws"]).status.success());
    fs::write(
        fx.root().join("ws/bad.ws"),
        "expand-url = \"{{WS_URL}}/ws/echo\"\ndata = \"x\"\nexpand-header = \"X: {{nope}}\"\n",
    )
    .unwrap();
    let out = fx.curly(&["lint", "ws"]);
    assert_eq!(out.status.code(), Some(1));
    let s = stdout(&out);
    assert!(
        s.contains("ws/bad.ws:2: error: `data` is not supported in .ws files"),
        "{s}"
    );
    assert!(s.contains("`{{nope}}` is not defined"), "{s}");
    let cmd = fx.curly(&["cmd", "ws/echo.ws"]);
    assert_eq!(cmd.status.code(), Some(2));
    assert!(
        stderr(&cmd).contains("is a WebSocket request; use `curly ws ws/echo.ws`"),
        "{}",
        stderr(&cmd)
    );
    let comp = stdout(&fx.curly_env(&["--", "curly", "run", "ws/"], &[("COMPLETE", "fish")]));
    assert!(comp.contains("ws/echo.ws\tEcho socket"), "{comp}");
}
