//! End-to-end tests for GraphQL requests: introspection, caching, validation,
//! completion, generation, and running.

mod common;

use std::fs;

use common::{Fixture, stderr, stdout};

fn introspect(fx: &Fixture) {
    let out = fx.curly(&["gql", "introspect", "graphql/ping.curl"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(
        s.contains(&format!(
            "Cached schema for {}/graphql",
            fx.server.base_url()
        )) && s.contains("Query (3 fields), Mutation (1 fields)"),
        "{s}"
    );
}

#[test]
fn graphql_requests_run_and_check_results() {
    let fx = Fixture::new();
    let token = fx.login_token();
    let out = fx.curly(&["run", "graphql", "--var", &format!("API_TOKEN={token}")]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("4 requests: 4 passed"),
        "{}",
        stdout(&out)
    );
    let body = stdout(&fx.curly(&["run", "graphql/get-user.curl", "--jq", ".data.user.name"]));
    assert_eq!(body.trim(), "\"Ada Lovelace\"");
    let verbose = stdout(&fx.curly(&["run", "graphql/get-user.curl", "-v", "--plain"]));
    assert!(
        verbose.contains("\"query\": \"query User($id: ID!) {\\n  user(id: $id)"),
        "the document is sent as a JSON string: {verbose}"
    );
}

#[test]
fn introspection_caches_schema_and_is_recorded_without_a_file() {
    let fx = Fixture::new();
    introspect(&fx);
    let cache = fs::read_dir(fx.root().join(".curly/cache/graphql"))
        .unwrap()
        .count();
    assert_eq!(cache, 1);
    let list = stdout(&fx.curly(&["history", "list"]));
    assert!(list.contains("POST") && list.contains("/graphql"), "{list}");
    let sdl = stdout(&fx.curly(&["gql", "schema", "graphql/get-user.curl"]));
    assert!(
        sdl.contains("type Query {")
            && sdl.contains("user(id: ID!): User")
            && sdl.contains("input NewUserInput {"),
        "{sdl}"
    );
    let check = fx.curly(&["gql", "check"]);
    assert_eq!(check.status.code(), Some(0), "{}", stdout(&check));
    assert!(stdout(&check).contains("4 GraphQL requests checked, 0 errors"));
}

#[test]
fn invalid_documents_are_reported_by_check_lint_and_run() {
    let fx = Fixture::new();
    let before = stdout(&fx.curly(&["gql", "check"]));
    assert!(
        before.contains("skip graphql/get-user.curl: no cached schema"),
        "{before}"
    );
    introspect(&fx);
    fs::write(
        fx.root().join("graphql/get-user.graphql"),
        "query User($id: ID!, $verbose: Boolean!) {\n  user(id: $id) {\n    id\n    nmae\n  }\n}\n",
    )
    .unwrap();
    let check = fx.curly(&["gql", "check", "graphql/get-user.curl"]);
    assert_eq!(check.status.code(), Some(1));
    let s = stdout(&check);
    assert!(
        s.contains("graphql/get-user.graphql:4:5: error: type `User` does not have a field `nmae`"),
        "{s}"
    );
    assert!(s.contains("graphql/get-user.graphql: error: required variable `$verbose: Boolean!` is missing from the variables file"), "{s}");
    let lint = fx.curly(&["lint", "graphql"]);
    assert_eq!(lint.status.code(), Some(1));
    assert!(
        stdout(&lint).contains(
            "graphql/get-user.graphql:4: error: type `User` does not have a field `nmae`"
        ),
        "{}",
        stdout(&lint)
    );
    let run = fx.curly(&["run", "graphql/get-user.curl"]);
    assert!(
        stderr(&run).contains(
            "warning: graphql/get-user.graphql:4:5: type `User` does not have a field `nmae`"
        ),
        "{}",
        stderr(&run)
    );
    assert_eq!(
        run.status.code(),
        Some(1),
        "the server's errors fail the `$.errors is absent` check"
    );
}

#[test]
fn completes_fields_at_a_position() {
    let fx = Fixture::new();
    let missing = fx.curly(&["gql", "complete", "graphql/get-user.graphql:3:5"]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(
        stderr(&missing).contains("no cached schema"),
        "{}",
        stderr(&missing)
    );
    introspect(&fx);
    let out = stdout(&fx.curly(&["gql", "complete", "graphql/get-user.graphql:3:5"]));
    let names: Vec<&str> = out.lines().map(|l| l.split('\t').next().unwrap()).collect();
    assert_eq!(names, vec!["id", "name", "email", "friends", "__typename"]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&fx.curly(&[
        "gql",
        "complete",
        "graphql/get-user.graphql:3:5",
        "--json",
    ])))
    .unwrap();
    assert_eq!(json[3]["type"], "[User!]!");
    let shell = stdout(&fx.curly_env(
        &["--", "curly", "gql", "new", "x", "--field", "Mut"],
        &[("COMPLETE", "fish")],
    ));
    assert!(shell.starts_with("Mutation.createUser\tUser!"), "{shell}");
}

#[test]
fn new_generates_valid_requests_from_the_schema() {
    let fx = Fixture::new();
    let no_schema = fx.curly(&["gql", "new", "graphql/list", "--field", "Query.users"]);
    assert_eq!(no_schema.status.code(), Some(2));
    introspect(&fx);
    let out = fx.curly(&["gql", "new", "graphql/list", "--field", "Query.users"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        fs::read_to_string(fx.root().join("graphql/list.graphql")).unwrap(),
        "query Users($limit: Int) {\n  users(limit: $limit) {\n    id\n    name\n    email\n  }\n}\n"
    );
    assert_eq!(
        fs::read_to_string(fx.root().join("graphql/list.vars.json")).unwrap(),
        "{\n  \"limit\": 1\n}\n"
    );
    let run = fx.curly(&["run", "graphql/list.curl", "--jq", ".data.users | length"]);
    assert_eq!(stdout(&run).trim(), "1");
    assert_eq!(
        fx.curly(&["run", "graphql/list.curl"]).status.code(),
        Some(0)
    );
    assert_eq!(
        fx.curly(&["gql", "new", "graphql/list"]).status.code(),
        Some(2),
        "existing files are not overwritten"
    );
    let plain = fx.curl(&["-sS", "-K", "envs/local.curl", "-K", "graphql/list.curl"]);
    assert!(
        stdout(&plain).contains("\"users\":[{\"id\":\"1\""),
        "generated requests run with plain curl: {}",
        stdout(&plain)
    );
}
