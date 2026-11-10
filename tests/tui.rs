//! Terminal UI: guards without a terminal, plus end-to-end runs in a
//! pseudo-terminal (via `script`) with scripted key presses.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{Fixture, stderr};

/// Runs `cmd` in a 24x90 pseudo-terminal, typing `keys` (each after a pause).
/// Returns the screen output with escape sequences stripped, or `None` if
/// `script` is unavailable.
fn in_pty(fx: &Fixture, cmd: &str, keys: &[&str]) -> Option<String> {
    let out_file = fx.dir.path().join("pty.out");
    let shell = format!("stty rows 24 cols 90; {cmd}");
    let mut c = Command::new("script");
    if cfg!(target_os = "linux") {
        c.args(["-q", "-e", "-c", &shell]).arg(&out_file);
    } else {
        c.arg("-q").arg(&out_file).args(["sh", "-c", &shell]);
    }
    let mut child = c
        .current_dir(fx.root())
        .env("BASE_URL", fx.server.base_url())
        .env(
            "CURLY_SECRET_STORE",
            format!("file:{}", fx.dir.path().join("secrets.json").display()),
        )
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    std::thread::sleep(Duration::from_millis(1500));
    for k in keys {
        stdin.write_all(k.as_bytes()).ok()?;
        stdin.flush().ok()?;
        std::thread::sleep(Duration::from_millis(400));
    }
    drop(stdin);
    let status = child.wait().ok()?;
    assert!(status.success(), "TUI exited with {status}");
    let raw = std::fs::read(&out_file).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let stripped = regex::Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]")
        .unwrap()
        .replace_all(&text, " ")
        .into_owned();
    Some(stripped)
}

#[test]
fn refuses_to_start_without_a_terminal() {
    let fx = Fixture::new();
    for args in [
        vec!["run", "users/get-user.curl", "--tui"],
        vec!["tui"],
        vec!["history", "show", "last", "--tui"],
    ] {
        let out = fx.curly(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            stderr(&out).contains("the TUI needs an interactive terminal"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    assert!(fx.curly(&["history", "list"]).status.success());
    assert_eq!(
        stderr(&fx.curly(&["history", "list"])),
        "",
        "the guard runs before any request is sent"
    );
    let conflict = fx.curly(&["run", "users/get-user.curl", "--tui", "--plain"]);
    assert_eq!(conflict.status.code(), Some(2));
    assert!(stderr(&conflict).contains("cannot be used with"));
}

#[test]
fn response_viewer_folds_json_in_a_real_terminal() {
    let fx = Fixture::new();
    let exe = env!("CARGO_BIN_EXE_curly");
    let Some(screen) = in_pty(
        &fx,
        &format!("{exe} run users/list-users.curl --tui"),
        &["j", "j", " ", "q"],
    ) else {
        eprintln!("skipping: `script` is not available");
        return;
    };
    assert!(
        screen.contains("HTTP/1.1 200 OK")
            && screen.contains("1 Body")
            && screen.contains("Ada Lovelace"),
        "{screen}"
    );
    assert!(
        screen.contains("… 3 keys"),
        "space folded the first user: {screen}"
    );
}

#[test]
fn history_browser_filters_entries() {
    let fx = Fixture::new();
    fx.curly(&["run", "users/get-user.curl"]);
    fx.curly(&["run", "health.curl"]);
    let exe = env!("CARGO_BIN_EXE_curly");
    let Some(screen) = in_pty(
        &fx,
        &format!("{exe} tui"),
        &["/", "h", "e", "a", "l", "\r", "q"],
    ) else {
        eprintln!("skipping: `script` is not available");
        return;
    };
    assert!(
        screen.contains("history")
            && screen.contains("health.curl")
            && screen.contains("users/get-user"),
        "{screen}"
    );
    assert!(
        screen.contains("j/k select · enter open · / filter · r re-run · q quit"),
        "{screen}"
    );
    assert!(
        screen.contains("▏"),
        "typing after / shows the filter prompt: {screen}"
    );
}
