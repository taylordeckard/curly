//! curly: API-workbench features on top of curl and plain files.
//!
//! Request files are plain curl config files (`curl -K file.curl`); curly adds
//! environments, secrets, history, and formatted output around the system curl.

pub mod assertions;
pub mod cli;
pub mod completion;
pub mod curlcmd;
pub mod curlconf;
pub mod curlexec;
pub mod docs;
pub mod filter;
pub mod folder;
pub mod graphql;
pub mod grpc;
pub mod history;
pub mod lint;
pub mod mock;
pub mod oauth;
pub mod openapi;
pub mod project;
pub mod redact;
pub mod report;
pub mod request;
pub mod runner;
pub mod secrets;
pub mod tls;
pub mod tui;
pub mod vars;
pub mod view;
pub mod ws;
