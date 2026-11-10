//! Shell completion: the dynamic protocol (fish/zsh), the real bash script,
//! and the values offered for files, environments, variables, and history.

mod common;

use std::process::Command;

use common::{Fixture, stdout};

/// Completes `words` (the last one is the word being completed) with the fish protocol.
fn fish(fx: &Fixture, words: &[&str]) -> Vec<(String, String)> {
    let mut args = vec!["--", "curly"];
    args.extend_from_slice(words);
    let out = fx.curly_env(&args, &[("COMPLETE", "fish")]);
    stdout(&out)
        .lines()
        .map(|l| {
            let (v, h) = l.split_once('\t').unwrap_or((l, ""));
            (v.to_string(), h.to_string())
        })
        .collect()
}

fn values(c: &[(String, String)]) -> Vec<&str> {
    c.iter()
        .map(|(v, _)| v.as_str())
        .filter(|v| !v.starts_with('-'))
        .collect()
}

#[test]
fn completes_subcommands_and_request_paths() {
    let fx = Fixture::new();
    let top = values(&fish(&fx, &[""])).join(" ");
    for cmd in [
        "init",
        "run",
        "cmd",
        "lint",
        "import",
        "auth",
        "env",
        "secret",
        "history",
        "completion",
    ] {
        assert!(top.contains(cmd), "{top}");
    }
    let run = fish(&fx, &["run", ""]);
    let v = values(&run);
    assert!(
        v.contains(&"users/") && v.contains(&"oauth/") && v.contains(&"health.curl"),
        "{v:?}"
    );
    assert!(
        !v.iter()
            .any(|x| ["data/", "schemas/", "scripts/", "envs/"].contains(x)),
        "folders without requests are hidden: {v:?}"
    );
    assert!(
        run.contains(&("health.curl".into(), "Health check".into())),
        "request names are shown as help"
    );
    assert_eq!(
        values(&fish(&fx, &["run", "users/get-m"])),
        vec!["users/get-missing-user.curl"]
    );
    assert_eq!(
        values(&fish(&fx, &["cmd", "oauth/br"])),
        vec!["oauth/browser/"]
    );
    assert!(values(&fish(&fx, &["auth", "login", "oauth/"])).contains(&"oauth/service-me.curl"));
}

#[test]
fn completes_environments_variables_and_reports() {
    let fx = Fixture::new();
    std::fs::write(
        fx.root().join("envs/staging.curl"),
        "variable = \"BASE_URL=https://staging.example.test\"\n",
    )
    .unwrap();
    assert_eq!(
        fish(&fx, &["run", "-e", ""]),
        vec![
            ("local".into(), "envs/local.curl (default)".into()),
            ("staging".into(), "envs/staging.curl".into())
        ]
    );
    let vars = fish(&fx, &["run", "x.curl", "--var", ""]);
    let names = values(&vars);
    for n in [
        "BASE_URL=",
        "user_id=",
        "expected_name=",
        "created_id=",
        "API_TOKEN=",
        "ACCESS_TOKEN=",
    ] {
        assert!(names.contains(&n), "{n} missing from {names:?}");
    }
    assert!(
        vars.contains(&(
            "expected_name=".into(),
            "Ada Lovelace (users/_folder.toml)".into()
        )),
        "{vars:?}"
    );
    let token_help = &vars.iter().find(|(v, _)| v == "API_TOKEN=").unwrap().1;
    assert!(token_help.starts_with("secret"), "{token_help}");
    let all = format!("{vars:?}");
    assert!(
        !all.contains(common::DEMO_PASSWORD) && !all.contains(&fx.server.oauth_client_secret()),
        "completion never shows secret values"
    );
    assert_eq!(
        values(&fish(&fx, &["run", "x.curl", "--var", "user_"])),
        vec!["user_id="]
    );
    assert!(fish(&fx, &["run", "x.curl", "--var", "user_id=2"]).is_empty());
    assert_eq!(
        values(&fish(&fx, &["run", ".", "--report", ""])),
        vec!["junit=", "json="]
    );
    assert!(values(&fish(&fx, &["run", ".", "--data", "data/"])).contains(&"data/users.csv"));
    assert!(
        values(&fish(&fx, &["import", "openapi", "imported/"])).contains(&"imported/openapi.yaml")
    );
}

#[test]
fn completes_history_ids_and_secret_names_without_creating_state() {
    let fx = Fixture::new();
    assert_eq!(
        values(&fish(&fx, &["history", "show", ""])),
        Vec::<&str>::new()
    );
    assert!(
        !fx.root().join(".curly").exists(),
        "completion must not create .curly/"
    );
    fx.curly(&["run", "users/get-user.curl"]);
    fx.curly_stdin(&["secret", "set", "MY_TOKEN"], "value-1234\n");
    let ids = fish(&fx, &["history", "show", ""]);
    assert_eq!(values(&ids), vec!["last", "1"]);
    assert_eq!(ids[1].1, "GET 200 users/get-user.curl");
    assert_eq!(
        fish(&fx, &["secret", "get", ""])[0],
        ("MY_TOKEN".into(), "env local".into())
    );
}

#[test]
fn zsh_protocol_and_registration() {
    let fx = Fixture::new();
    let out = fx.curly_env(
        &["--", "curly", "run", "users/get-u"],
        &[("COMPLETE", "zsh"), ("_CLAP_COMPLETE_INDEX", "2")],
    );
    assert_eq!(stdout(&out).trim(), "users/get-user.curl:Get user");
    let script = stdout(&fx.curly(&["completion", "zsh"]));
    assert!(
        script.starts_with("#compdef curly")
            && script.contains("function _clap_dynamic_completer_curly()"),
        "{script}"
    );
    assert!(
        script.contains(env!("CARGO_BIN_EXE_curly")),
        "script calls this binary"
    );
    let check = Command::new("zsh")
        .args(["-f", "-c", "autoload -Uz compinit && compinit -u -D && source /dev/stdin && print ${+functions[_clap_dynamic_completer_curly]}"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn();
    if let Ok(mut child) = check {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "1",
            "zsh loads the completion function"
        );
    }
}

#[test]
fn bash_script_completes_through_the_real_function() {
    let fx = Fixture::new();
    let script = fx.root().join("curly.bash");
    std::fs::write(&script, stdout(&fx.curly(&["completion", "bash"]))).unwrap();
    let complete = |words: &str, cword: usize| -> Vec<String> {
        let shell = format!(
            "source {}; COMP_WORDS=({words}); COMP_CWORD={cword}; COMP_TYPE=9; _clap_complete_curly curly \"${{COMP_WORDS[COMP_CWORD]}}\" curly; printf '%s\\n' \"${{COMPREPLY[@]}}\"",
            script.display()
        );
        let out = Command::new("bash")
            .args(["--norc", "--noprofile", "-c", &shell])
            .current_dir(fx.root())
            .env_remove("COMPLETE")
            .output()
            .unwrap();
        stdout(&out)
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    };
    assert_eq!(
        complete("curly run users/get-c", 2),
        vec!["users/get-created-user.curl"]
    );
    assert_eq!(complete("curly run -e l", 3), vec!["local"]);
    assert!(complete("curly hi", 1).contains(&"history".to_string()));
    let fish_script = stdout(&fx.curly(&["completion", "fish"]));
    assert!(
        fish_script.starts_with("complete --keep-order --exclusive --command curly"),
        "{fish_script}"
    );
}
