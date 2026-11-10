//! End-to-end tests for gRPC requests: reflection and .proto descriptors,
//! all four method kinds, metadata auth, errors, generation, and redaction.

mod common;

use std::fs;

use common::{Fixture, stderr, stdout};

#[test]
fn lists_and_describes_with_reflection() {
    let fx = Fixture::new();
    let addr = fx.server.grpc_addr.to_string();
    let list = stdout(&fx.curly(&["grpc", "list", &addr]));
    assert!(list.starts_with("curly.test.v1.UserService\n"), "{list}");
    assert!(
        list.contains(
            "  ListUsers(curly.test.v1.ListUsersRequest) returns (stream curly.test.v1.User)"
        ),
        "{list}"
    );
    assert!(
        list.contains("  WhoAmI(google.protobuf.Empty) returns"),
        "imports resolve through reflection: {list}"
    );
    assert!(!list.contains("grpc.reflection"), "{list}");
    let same = stdout(&fx.curly(&["grpc", "list", "grpc/get-user.grpc"]));
    assert_eq!(same, list);
    let desc = stdout(&fx.curly(&["grpc", "describe", "grpc/create-users.grpc"]));
    assert!(desc.starts_with("rpc curly.test.v1.UserService.CreateUsers(stream curly.test.v1.NewUser) returns (curly.test.v1.CreateUsersResponse)"), "{desc}");
    assert!(
        desc.contains("  repeated int64 ids = 2;") && desc.contains("\"email\": \"string\""),
        "{desc}"
    );
}

#[test]
fn runs_every_method_kind() {
    let fx = Fixture::new();
    let token = fx.login_token();
    let out = fx.curly(&["run", "grpc", "--var", &format!("API_TOKEN={token}")]);
    let s = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{s}\n{}", stderr(&out));
    assert!(
        s.contains("✓ grpc/get-missing-user.grpc  NOT_FOUND")
            && s.contains("✓ grpc/get-user.grpc  OK"),
        "{s}"
    );
    assert!(s.contains("6 requests: 6 passed"), "{s}");
    let unary = stdout(&fx.curly(&["run", "grpc/get-user.grpc", "--jq", "{name, role}"]));
    assert_eq!(
        unary,
        "{\n  \"name\": \"Ada Lovelace\",\n  \"role\": \"ROLE_ADMIN\"\n}\n"
    );
    let stream = stdout(&fx.curly(&["run", "grpc/list-users.grpc", "--jq", "[.[].id]"]));
    assert_eq!(
        stream, "[\n  \"1\",\n  \"2\"\n]\n",
        "int64 fields use proto3 JSON strings"
    );
    let shout = stdout(&fx.curly(&["run", "grpc/shout.grpc", "--path", "$[*].text"]));
    assert_eq!(shout, "\"HELLO\"\n\"WORLD\"\n");
    let full = stdout(&fx.curly(&["run", "grpc/get-user.grpc"]));
    assert!(full.starts_with("gRPC 0 OK  "), "{full}");
}

#[test]
fn metadata_auth_and_status_errors() {
    let fx = Fixture::new();
    let denied = fx.curly(&["run", "grpc/whoami.grpc", "--body"]);
    assert_eq!(denied.status.code(), Some(1));
    assert!(
        stdout(&denied).contains("\"status\": \"UNAUTHENTICATED\""),
        "{}",
        stdout(&denied)
    );
    assert!(
        stderr(&denied).contains("✗ status is OK: got 16"),
        "{}",
        stderr(&denied)
    );
    let token = fx.login_token();
    let ok = fx.curly(&[
        "run",
        "grpc/whoami.grpc",
        "-v",
        "--var",
        &format!("API_TOKEN={token}"),
    ]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
    assert!(
        stdout(&ok).contains("> authorization: Bearer [REDACTED]"),
        "{}",
        stdout(&ok)
    );
    let db = String::from_utf8_lossy(&fs::read(fx.root().join(".curly/history.db")).unwrap())
        .into_owned();
    assert!(!db.contains(&token), "metadata secrets never reach history");
}

#[test]
fn bad_requests_fail_clearly() {
    let fx = Fixture::new();
    fs::write(fx.root().join("grpc/bad-field.grpc"), "expand-url = \"grpc://{{GRPC_TARGET}}/curly.test.v1.UserService/GetUser\"\ndata = \"{\\\"nope\\\": 1}\"\n").unwrap();
    let out = fx.curly(&["run", "grpc/bad-field.grpc"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("request does not match curly.test.v1.GetUserRequest"),
        "{}",
        stderr(&out)
    );
    fs::write(
        fx.root().join("grpc/bad-method.grpc"),
        "expand-url = \"grpc://{{GRPC_TARGET}}/curly.test.v1.UserService/Nope\"\n",
    )
    .unwrap();
    let out = fx.curly(&["run", "grpc/bad-method.grpc"]);
    assert!(
        stderr(&out).contains(
            "has no method `Nope` (methods: GetUser, ListUsers, CreateUsers, Shout, WhoAmI)"
        ),
        "{}",
        stderr(&out)
    );
    let down = fx.curly(&[
        "run",
        "grpc/get-user.grpc",
        "--var",
        "GRPC_TARGET=127.0.0.1:9",
    ]);
    assert_eq!(down.status.code(), Some(3), "{}", stderr(&down));
    assert!(
        stderr(&down).contains("Failed to connect to 127.0.0.1:9"),
        "{}",
        stderr(&down)
    );
    let cmd = fx.curly(&["cmd", "grpc/get-user.grpc"]);
    assert!(
        stderr(&cmd).contains("is a gRPC request"),
        "{}",
        stderr(&cmd)
    );
}

#[test]
fn lint_and_generation() {
    let fx = Fixture::new();
    fs::remove_file(fx.root().join("grpc/get-user.grpc")).unwrap();
    fs::remove_file(fx.root().join("grpc/get-user.test.toml")).unwrap();
    let _ = fs::write(fx.root().join("grpc/_folder.toml"), "");
    let out = fx.curly(&[
        "grpc",
        "new",
        "grpc/get-user",
        "--method",
        "curly.test.v1.UserService/GetUser",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = fs::read_to_string(fx.root().join("grpc/get-user.grpc")).unwrap();
    assert!(
        text.contains("--expand-url grpc://{{GRPC_TARGET}}/curly.test.v1.UserService/GetUser")
            && text.contains("--data \"{\\\"id\\\":\\\"1\\\"}\""),
        "{text}"
    );
    assert_eq!(
        fx.curly(&["run", "grpc/get-user.grpc"]).status.code(),
        Some(0)
    );
    assert!(fx.curly(&["lint", "grpc"]).status.success());
    fs::write(fx.root().join("grpc/lint-me.grpc"), "url = \"grpc://h:1/a.B/C\"\nlocation\nexpand-header = \"authorization: {{undefined_thing}}\"\n").unwrap();
    let lint = stdout(&fx.curly(&["lint", "grpc"]));
    assert!(
        lint.contains("grpc/lint-me.grpc:2: error: `location` is not supported in .grpc files"),
        "{lint}"
    );
    assert!(
        lint.contains("`{{undefined_thing}}` is not defined"),
        "{lint}"
    );
}
