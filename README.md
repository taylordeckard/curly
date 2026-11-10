# curly

An API workbench around your system curl. Requests are plain curl config files
that you keep in git and can always run with `curl -K file.curl`. curly adds
environments, secrets, tests, history, and a few other tools, all locally: no
accounts, cloud sync, or telemetry.

How it relates to curl:

- HTTP requests (including GraphQL and OAuth token calls) run through your
  system `curl` binary, unchanged. curly reads curl's trace to show and record
  exactly what was sent.
- WebSocket (`.ws`) and gRPC (`.grpc`) requests use built-in clients. Their
  files use curl syntax, but plain curl cannot run them.
- curly parses curl config files itself to lint, document, and redact them.

## Install

Needs Rust 1.85+ and curl 8.3+ (for `--variable` and `--expand-*`).

```sh
cargo install --path .
```

Shell completion: `source <(curly completion zsh)` (or `bash`, `fish`).

## A request file

```text
# @name Get user
# @description Fetches one user by id.
# @tags users
--expand-url {{BASE_URL}}/users/{{user_id}}
--header "Accept: application/json"
--expand-header "Authorization: Bearer {{API_TOKEN}}"
```

`# @name`, `# @description`, and `# @tags` are comments to curl; curly uses them
for listings and docs. Everything curl does not understand (tests, auth flows,
run order) lives in sidecar files next to the request, never in the request.

Plain curl, from the collection root:

```sh
curl -K envs/local.curl -K users/get-user.curl
```

## Quick start

```sh
curly init my-api && cd my-api
curly new users/get-user.curl -- curl -H 'Authorization: Bearer abc123' https://api.example.com/users/1
curly run users/get-user.curl
```

`curly new` turns a pasted curl command (also `pbpaste | curly new x.curl --stdin`)
into a request file: the host becomes `{{BASE_URL}}`, and credentials become
variables whose values go to the keychain, never into the file.

To try curl arguments without saving anything:

```sh
curly curl https://api.example.com/users/1 --jq .name
curly curl --save users/get-user.curl -H 'Accept: application/json' https://api.example.com/users/1
```

## Collection layout

```text
my-api/
  curly.toml                project settings (default environment, redaction)
  _folder.toml              run order, variable defaults, [auth] for a folder
  envs/local.curl           an environment: --variable lines curl reads with -K
  envs/local.secrets.curl   optional, git-ignored
  users/get-user.curl       a request
  users/get-user.test.toml  its checks and captures
  .curly/                   local state (history, secret names); git-ignored
```

Variables follow curl's rules, with this precedence (lowest first): folder
`[vars]`, environment file, secrets file, keychain, OAuth token, captured
values, data rows, `--var`. curl has no inline defaults; give a variable a
default in an environment file with `--variable %NAME=default`, which also lets
an exported shell variable override it.

## Running and viewing

```sh
curly run users/get-user.curl -e local         # formatted response
curly run users/get-user.curl -r | jq .        # raw body, for pipes
curly run users/get-user.curl --jq .name       # jq filter (--path for JSONPath)
curly run users/get-user.curl -v               # request, headers, timings
curly run users/ --bail                        # a folder, in _folder.toml order
curly run users/get-user.curl --data data/users.csv   # once per row
curly run . --report junit=report.xml
curly cmd users/get-user.curl                  # the equivalent plain curl command
```

## Tests and captures

`users/get-user.test.toml`:

```toml
[expect]
status = 200
schema = "schemas/user.json"
max_time_ms = 1000

[[expect.json]]
path = "$.name"
eq = "{{expected_name}}"

[capture]
user_id = "$.id"
token = { from = "$.access_token", secret = true }
```

Captures feed later requests in the same run. Sources: `$.path`, `jq:EXPR`,
`header:NAME`, `regex:RE`, `status`, `body`.

## Secrets and redaction

```sh
curly secret set API_TOKEN -e local    # hidden prompt, or stdin; never argv
curly secret list
```

Secrets live in the OS keychain (or a mode-0600 file with
`[secrets] store = "file"`); `.curly/secrets.json` keeps only their names. A
run reads only the secrets that request uses, and an exported shell variable
of the same name skips the keychain.

Output, history, and reports redact by default: `Authorization`, `Cookie`, and
API-key headers; secret variable values; token, password, and key fields in
JSON, query strings, and form bodies. Add more in `curly.toml`:

```toml
[redact]
headers = ["x-session-jwt"]
variables = ["^SESSION_COOKIE$"]
```

`--show-secrets` reveals values in output only; history and reports stay redacted.

## More

| Command | What it does |
| --- | --- |
| `curly import openapi SPEC` | Requests, examples, and schema checks from OpenAPI 3.x or Swagger 2.0 |
| `curly auth login FOLDER` | OAuth 2.0 (client credentials, authorization code with PKCE); tokens cached in the keychain |
| `curly gql introspect\|new` | GraphQL schema caching, validation, and request generation |
| `curly grpc list\|describe\|new` | gRPC via server reflection or `.proto` files |
| `curly ws FILE [-i]` | WebSocket: scripted `[[step]]`s or interactive chat |
| `curly mock` | Local mock server (loopback only) from a spec or saved `*.example.json` responses |
| `curly docs` | Static HTML or Markdown reference for the collection |
| `curly history list\|show\|diff\|rerun` | Every run is recorded in `.curly/history.db` |
| `curly tui` | Terminal UI for history and responses |
| `curly lint` | Checks curl validity, undefined variables, and hardcoded credentials |
| `curly fmt` | Rewrites files in command-line style (`--header "..."`) |

## Example collection

`examples/collection` exercises every feature against a local test server
(REST, OAuth, GraphQL, WebSocket, gRPC):

```sh
cargo run -p curly-testserver           # 127.0.0.1:8787, gRPC on 8788
```

In another terminal, using the OAuth client secret the server printed at startup:

```sh
cd examples/collection
export OAUTH_CLIENT_SECRET=...          # "secret for this run: ..."
curly auth login oauth/browser          # optional: authorization code + PKCE in your browser
curly run .
```

Without the secret and the browser login, the two `oauth/` requests report
errors and everything else still runs.

## Development

```sh
cargo test
cargo clippy --all-targets
```

## License

MIT
