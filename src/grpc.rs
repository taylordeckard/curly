//! gRPC requests (`.grpc` files).
//!
//! A `.grpc` file uses curl config syntax:
//!
//! ```text
//! expand-url = "grpc://{{GRPC_TARGET}}/curly.test.v1.UserService/GetUser"
//! expand-header = "authorization: Bearer {{API_TOKEN}}"   # request metadata
//! data = "{\"id\": 1}"                                    # one JSON message per data line
//! proto = "proto/users.proto"                             # optional; else server reflection
//! ```
//!
//! `grpc://` is plaintext HTTP/2, `grpcs://` is TLS (TLS 1.3 unless `tlsv1.2`).
//! Messages are proto3 JSON; every method kind (unary, client, server, and
//! bidirectional streaming) goes through one streaming call. The response's
//! `status` is the gRPC status code (0 = OK), so sidecars use `status = 0`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use prost::Message as _;
use prost_reflect::{
    DescriptorPool, DynamicMessage, Kind, MessageDescriptor, MethodDescriptor, SerializeOptions,
};
use serde_json::{Value, json};
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::metadata::{
    AsciiMetadataKey, AsciiMetadataValue, BinaryMetadataKey, BinaryMetadataValue, MetadataMap,
};
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Status};

use crate::curlconf::{RequestSpec, substitute};
use crate::curlexec::{Curl, Exchange, RequestRecord, ResponseRecord, Timing};
use crate::project::Project;
use crate::request::{RunOptions, RunResult, finish, prepare};
use crate::vars::{Source, parse_variable_arg};

/// Options a `.grpc` file may use (by base name).
pub const SUPPORTED_OPTIONS: &[&str] = &[
    "url",
    "header",
    "data",
    "proto",
    "import-path",
    "max-time",
    "connect-timeout",
    "cacert",
    "tlsv1.2",
    "tlsv1.3",
    "user-agent",
    "variable",
];

/// gRPC status code names, indexed by code.
pub const CODE_NAMES: &[&str] = &[
    "OK",
    "CANCELLED",
    "UNKNOWN",
    "INVALID_ARGUMENT",
    "DEADLINE_EXCEEDED",
    "NOT_FOUND",
    "ALREADY_EXISTS",
    "PERMISSION_DENIED",
    "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION",
    "ABORTED",
    "OUT_OF_RANGE",
    "UNIMPLEMENTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DATA_LOSS",
    "UNAUTHENTICATED",
];

/// Name of gRPC status `code`.
pub fn code_name(code: u16) -> &'static str {
    CODE_NAMES.get(code as usize).copied().unwrap_or("UNKNOWN")
}

/// Code for a gRPC status name such as `NOT_FOUND`.
pub fn code_from_name(name: &str) -> Option<u16> {
    CODE_NAMES
        .iter()
        .position(|n| n.eq_ignore_ascii_case(name))
        .map(|i| i as u16)
}

/// A resolved gRPC call.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    /// `host:port`.
    pub authority: String,
    /// Use TLS (`grpcs://`).
    pub tls: bool,
    /// Fully qualified service, e.g. `curly.test.v1.UserService`.
    pub service: String,
    /// Method name, e.g. `GetUser`.
    pub method: String,
    /// Metadata as `(key, value)`; `-bin` keys carry base64.
    pub metadata: Vec<(String, String)>,
    /// JSON messages to send.
    pub messages: Vec<String>,
    /// `.proto` files (collection-relative); empty means reflection.
    pub protos: Vec<PathBuf>,
    /// Import paths for `protos`.
    pub import_paths: Vec<PathBuf>,
    /// Per-call deadline.
    pub timeout: Option<Duration>,
    /// Connect timeout.
    pub connect_timeout: Duration,
    /// Allow TLS 1.2.
    pub tls12: bool,
    /// Extra CA bundle.
    pub cacert: Option<PathBuf>,
}

impl Target {
    /// `grpc://host:port/pkg.Service/Method`.
    pub fn url(&self) -> String {
        format!(
            "{}://{}/{}/{}",
            if self.tls { "grpcs" } else { "grpc" },
            self.authority,
            self.service,
            self.method
        )
    }
}

/// Options in a `.grpc` file that curly does not support (for lint).
pub fn unsupported_options(spec: &RequestSpec) -> Vec<(usize, String)> {
    spec.config
        .entries
        .iter()
        .filter(|e| !SUPPORTED_OPTIONS.contains(&e.base_name()))
        .map(|e| {
            (
                e.line,
                format!(
                    "`{}` is not supported in .grpc files (supported: {})",
                    e.option,
                    SUPPORTED_OPTIONS.join(", ")
                ),
            )
        })
        .collect()
}

/// Parts of a `grpc://` or `grpcs://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcUrl {
    /// `grpcs://`.
    pub tls: bool,
    /// `host:port`.
    pub authority: String,
    /// `(service, method)` when the URL has a `/package.Service/Method` path.
    pub method: Option<(String, String)>,
}

/// Splits `grpc://host:port/pkg.Svc/Method` (the path part is optional).
pub fn parse_url(url: &str) -> Result<GrpcUrl> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("grpcs://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("grpc://") {
        (false, r)
    } else {
        bail!("gRPC url must start with grpc:// or grpcs:// (got `{url}`)");
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() {
        bail!("gRPC url `{url}` has no host:port");
    }
    let method = path
        .trim_end_matches('/')
        .rsplit_once('/')
        .map(|(s, m)| (s.to_string(), m.to_string()))
        .filter(|(s, m)| !s.is_empty() && !m.is_empty());
    Ok(GrpcUrl {
        tls,
        authority: authority.to_string(),
        method,
    })
}

/// Builds the target from a parsed `.grpc` file and variable values.
pub fn target(
    project: &Project,
    spec: &RequestSpec,
    vars: &BTreeMap<String, String>,
) -> Result<Target> {
    if let Some((line, msg)) = unsupported_options(spec).into_iter().next() {
        bail!("{}:{line}: {msg}", spec.path.display());
    }
    let mut vars = vars.clone();
    for (_, arg) in &spec.variables {
        if let (name, Source::File { path }) = parse_variable_arg(arg)? {
            vars.insert(
                name,
                std::fs::read_to_string(project.root.join(&path))
                    .with_context(|| format!("reading {path}"))?,
            );
        } else if let (name, Source::Literal { value }) = parse_variable_arg(arg)? {
            vars.insert(name, value);
        }
    }
    let mut url = String::new();
    let mut t = Target {
        authority: String::new(),
        tls: false,
        service: String::new(),
        method: String::new(),
        metadata: vec![],
        messages: vec![],
        protos: vec![],
        import_paths: vec![],
        timeout: None,
        connect_timeout: Duration::from_secs(10),
        tls12: false,
        cacert: None,
    };
    for e in &spec.config.entries {
        let raw = e.value.clone().unwrap_or_default();
        let value = if e.is_expanded() {
            substitute(&raw, &vars)
                .map_err(|m| anyhow::anyhow!("{}:{}: {m}", spec.path.display(), e.line))?
        } else {
            raw
        };
        match e.base_name() {
            "url" => url = value,
            "header" => {
                let (k, v) = value.split_once(':').with_context(|| {
                    format!(
                        "{}:{}: header needs `name: value`",
                        spec.path.display(),
                        e.line
                    )
                })?;
                t.metadata
                    .push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
            "user-agent" => t.metadata.push(("user-agent".into(), value)),
            "data" => t.messages.push(match value.strip_prefix('@') {
                Some(file) => std::fs::read_to_string(project.root.join(file))
                    .with_context(|| format!("reading {file}"))?,
                None => value,
            }),
            "proto" => t.protos.push(PathBuf::from(value)),
            "import-path" => t.import_paths.push(PathBuf::from(value)),
            "max-time" => {
                t.timeout = Some(Duration::from_secs_f64(
                    value.parse().context("max-time must be seconds")?,
                ))
            }
            "connect-timeout" => {
                t.connect_timeout = Duration::from_secs_f64(
                    value.parse().context("connect-timeout must be seconds")?,
                )
            }
            "cacert" => t.cacert = Some(PathBuf::from(value)),
            "tlsv1.2" => t.tls12 = true,
            _ => {}
        }
    }
    for p in t.protos.iter().chain(&t.import_paths) {
        if p.is_absolute()
            || p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            bail!(
                "{}: `{}` must be a path inside the collection",
                spec.path.display(),
                p.display()
            );
        }
    }
    let GrpcUrl {
        tls,
        authority,
        method,
    } = parse_url(&url)?;
    let (service, method) = method.with_context(|| {
        format!(
            "{}: url must end with /package.Service/Method",
            spec.path.display()
        )
    })?;
    (t.tls, t.authority, t.service, t.method) = (tls, authority, service, method);
    Ok(t)
}

/// Codec that encodes and decodes `DynamicMessage`s.
#[derive(Clone)]
struct DynamicCodec(MessageDescriptor);

struct DynEncoder;
struct DynDecoder(MessageDescriptor);

impl Encoder for DynEncoder {
    type Item = DynamicMessage;
    type Error = Status;
    fn encode(&mut self, item: DynamicMessage, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        item.encode(dst)
            .map_err(|e| Status::internal(e.to_string()))
    }
}

impl Decoder for DynDecoder {
    type Item = DynamicMessage;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<DynamicMessage>, Status> {
        DynamicMessage::decode(self.0.clone(), src)
            .map(Some)
            .map_err(|e| Status::internal(e.to_string()))
    }
}

impl Codec for DynamicCodec {
    type Encode = DynamicMessage;
    type Decode = DynamicMessage;
    type Encoder = DynEncoder;
    type Decoder = DynDecoder;
    fn encoder(&mut self) -> DynEncoder {
        DynEncoder
    }
    fn decoder(&mut self) -> DynDecoder {
        DynDecoder(self.0.clone())
    }
}

/// Opens a channel to `authority` (plaintext or TLS with ALPN h2).
async fn channel(project: &Project, t: &Target) -> Result<Channel> {
    if !t.tls {
        let ep = Endpoint::from_shared(format!("http://{}", t.authority))?
            .connect_timeout(t.connect_timeout);
        return ep
            .connect()
            .await
            .with_context(|| format!("Failed to connect to {}", t.authority));
    }
    let config = crate::tls::client_config(&project.root, t.tls12, t.cacert.as_deref(), &[b"h2"])?;
    let authority = t.authority.clone();
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&authority)
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let server_name = rustls_pki_types::ServerName::try_from(host.clone())?.to_owned();
    let connector = tower::service_fn(move |_uri: tonic::transport::Uri| {
        let (config, authority, server_name) =
            (config.clone(), authority.clone(), server_name.clone());
        async move {
            let tcp = tokio::net::TcpStream::connect(&authority).await?;
            let tls = tokio_rustls::TlsConnector::from(config)
                .connect(server_name, tcp)
                .await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
        }
    });
    let ep = Endpoint::from_shared(format!("http://{}", t.authority))?
        .origin(format!("https://{}", t.authority).parse()?)
        .connect_timeout(t.connect_timeout);
    ep.connect_with_connector(connector)
        .await
        .with_context(|| format!("Failed to connect to {}", t.authority))
}

/// Adds descriptor protos to `pool`, dependencies first.
fn add_protos(
    pool: &mut DescriptorPool,
    mut files: Vec<prost_types::FileDescriptorProto>,
) -> Result<()> {
    while !files.is_empty() {
        let before = files.len();
        let mut rest = Vec::new();
        for f in files {
            if f.dependency
                .iter()
                .all(|d| pool.get_file_by_name(d).is_some())
            {
                pool.add_file_descriptor_proto(f)?;
            } else {
                rest.push(f);
            }
        }
        if rest.len() == before {
            bail!(
                "reflection did not return these dependencies: {}",
                rest.iter()
                    .flat_map(|f| f.dependency.clone())
                    .filter(|d| pool.get_file_by_name(d).is_none())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        files = rest;
    }
    Ok(())
}

/// Generates a reflection client for one protocol version (v1 or v1alpha).
macro_rules! reflection_impl {
    ($name:ident, $pb:path) => {
        /// Talks to the server reflection service.
        async fn $name(channel: Channel, symbols: &[String], list: bool) -> Result<(Vec<String>, Vec<prost_types::FileDescriptorProto>), Status> {
            use $pb as pb;
            use pb::server_reflection_request::MessageRequest;
            use pb::server_reflection_response::MessageResponse;
            let mut client = pb::server_reflection_client::ServerReflectionClient::new(channel);
            let mut services = Vec::new();
            let mut files: BTreeMap<String, prost_types::FileDescriptorProto> = BTreeMap::new();
            let mut pending: Vec<MessageRequest> = symbols.iter().cloned().map(MessageRequest::FileContainingSymbol).collect();
            if list {
                pending.push(MessageRequest::ListServices(String::new()));
            }
            while let Some(req) = pending.pop() {
                let request = pb::ServerReflectionRequest { host: String::new(), message_request: Some(req) };
                let mut stream = client.server_reflection_info(tokio_stream::iter(vec![request])).await?.into_inner();
                while let Some(resp) = stream.message().await? {
                    match resp.message_response {
                        Some(MessageResponse::FileDescriptorResponse(fd)) => {
                            for bytes in fd.file_descriptor_proto {
                                let file = prost_types::FileDescriptorProto::decode(bytes.as_slice()).map_err(|e| Status::internal(e.to_string()))?;
                                for dep in &file.dependency {
                                    if !files.contains_key(dep) {
                                        pending.push(MessageRequest::FileByFilename(dep.clone()));
                                    }
                                }
                                files.insert(file.name().to_string(), file);
                            }
                        }
                        Some(MessageResponse::ListServicesResponse(l)) => services.extend(l.service.into_iter().map(|s| s.name)),
                        Some(MessageResponse::ErrorResponse(e)) => return Err(Status::new(Code::from(e.error_code), e.error_message)),
                        _ => {}
                    }
                }
                pending.retain(|r| !matches!(r, MessageRequest::FileByFilename(n) if files.contains_key(n)));
            }
            Ok((services, files.into_values().collect()))
        }
    };
}

reflection_impl!(reflect_v1, tonic_reflection::pb::v1);
reflection_impl!(reflect_v1alpha, tonic_reflection::pb::v1alpha);

/// Asks the server for descriptors (v1, falling back to v1alpha).
async fn reflect(
    channel: Channel,
    symbols: &[String],
    list: bool,
) -> Result<(Vec<String>, Vec<prost_types::FileDescriptorProto>)> {
    match reflect_v1(channel.clone(), symbols, list).await {
        Ok(r) => Ok(r),
        Err(s) if s.code() == Code::Unimplemented => reflect_v1alpha(channel, symbols, list)
            .await
            .map_err(|s| anyhow::anyhow!("server reflection failed: {}", s.message())),
        Err(s) => bail!(
            "server reflection failed: {} {}",
            code_name(s.code() as u16),
            s.message()
        ),
    }
}

/// Builds a descriptor pool from `.proto` files or server reflection.
async fn descriptors(
    project: &Project,
    t: &Target,
    channel: Channel,
    symbols: &[String],
    list: bool,
) -> Result<(DescriptorPool, Vec<String>)> {
    let mut pool = DescriptorPool::new();
    if !t.protos.is_empty() {
        let mut includes: Vec<PathBuf> = t
            .import_paths
            .iter()
            .map(|p| project.root.join(p))
            .collect();
        for p in &t.protos {
            includes.push(
                project
                    .root
                    .join(p)
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| project.root.clone()),
            );
        }
        let names: Vec<PathBuf> = t
            .protos
            .iter()
            .map(|p| PathBuf::from(p.file_name().unwrap_or_default()))
            .collect();
        let fds = protox::compile(&names, &includes)
            .map_err(|e| anyhow::anyhow!("compiling .proto files: {e}"))?;
        add_protos(&mut pool, fds.file)?;
        let services = pool.services().map(|s| s.full_name().to_string()).collect();
        return Ok((pool, services));
    }
    let (services, files) = reflect(channel, symbols, list).await?;
    add_protos(&mut pool, files)?;
    Ok((pool, services))
}

fn method_descriptor(pool: &DescriptorPool, t: &Target) -> Result<MethodDescriptor> {
    let service = pool
        .get_service_by_name(&t.service)
        .with_context(|| format!("service `{}` not found", t.service))?;
    let found = service.methods().find(|m| m.name() == t.method);
    found.with_context(|| {
        let names: Vec<String> = service.methods().map(|m| m.name().to_string()).collect();
        format!(
            "`{}` has no method `{}` (methods: {})",
            t.service,
            t.method,
            names.join(", ")
        )
    })
}

/// proto3 JSON for a message, including default-valued fields.
pub fn to_json(msg: &DynamicMessage) -> Value {
    let mut ser = serde_json::Serializer::new(Vec::new());
    let _ = msg.serialize_with_options(
        &mut ser,
        &SerializeOptions::new().skip_default_fields(false),
    );
    serde_json::from_slice(&ser.into_inner()).unwrap_or(Value::Null)
}

fn metadata_pairs(map: &MetadataMap) -> Vec<(String, String)> {
    map.clone()
        .into_headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Performs the call and returns the exchange (status = gRPC code).
async fn call(project: &Project, t: &Target) -> Result<Exchange> {
    let started = Instant::now();
    let channel = channel(project, t).await?;
    let (pool, _) = descriptors(
        project,
        t,
        channel.clone(),
        std::slice::from_ref(&t.service),
        false,
    )
    .await?;
    let method = method_descriptor(&pool, t)?;
    let mut inputs: Vec<DynamicMessage> = Vec::new();
    for text in if t.messages.is_empty() {
        vec!["{}".to_string()]
    } else {
        t.messages.clone()
    } {
        let value: Value = serde_json::from_str(&text).with_context(|| {
            format!(
                "request data is not JSON: {}",
                text.chars().take(80).collect::<String>()
            )
        })?;
        let items = match value {
            Value::Array(items) if method.is_client_streaming() => items,
            other => vec![other],
        };
        for item in items {
            inputs.push(
                DynamicMessage::deserialize(method.input(), item).with_context(|| {
                    format!("request does not match {}", method.input().full_name())
                })?,
            );
        }
    }
    if !method.is_client_streaming() && inputs.len() != 1 {
        bail!(
            "{} takes exactly one request message, got {}",
            method.full_name(),
            inputs.len()
        );
    }
    let sent_json: Vec<Value> = inputs.iter().map(to_json).collect();
    let mut request = tonic::Request::new(tokio_stream::iter(inputs));
    for (k, v) in &t.metadata {
        if k.ends_with("-bin") {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(v)
                .with_context(|| format!("metadata `{k}` must be base64"))?;
            request.metadata_mut().append_bin(
                BinaryMetadataKey::from_bytes(k.as_bytes())?,
                BinaryMetadataValue::from_bytes(&bytes),
            );
        } else {
            request.metadata_mut().append(
                AsciiMetadataKey::from_bytes(k.as_bytes())?,
                AsciiMetadataValue::try_from(v.as_str())?,
            );
        }
    }
    if let Some(d) = t.timeout {
        request.set_timeout(d);
    }
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready()
        .await
        .with_context(|| format!("Failed to connect to {}", t.authority))?;
    let path =
        tonic::codegen::http::uri::PathAndQuery::try_from(format!("/{}/{}", t.service, t.method))?;
    let mut headers = Vec::new();
    let mut received = Vec::new();
    let status = match grpc
        .streaming(request, path, DynamicCodec(method.output()))
        .await
    {
        Ok(resp) => {
            headers.extend(metadata_pairs(resp.metadata()));
            let mut stream = resp.into_inner();
            let mut status = Status::ok("");
            loop {
                match stream.message().await {
                    Ok(Some(m)) => received.push(to_json(&m)),
                    Ok(None) => break,
                    Err(s) => {
                        status = s;
                        break;
                    }
                }
            }
            if let Ok(Some(trailers)) = stream.trailers().await {
                headers.extend(metadata_pairs(&trailers));
            }
            status
        }
        Err(s) => {
            headers.extend(metadata_pairs(s.metadata()));
            s
        }
    };
    let code = status.code() as u16;
    let body = if code != 0 {
        json!({"code": code, "status": code_name(code), "message": status.message()})
    } else if method.is_server_streaming() {
        Value::Array(received)
    } else {
        received.into_iter().next().unwrap_or(Value::Null)
    };
    let body = serde_json::to_vec_pretty(&body)?;
    let req_body = serde_json::to_vec_pretty(&if sent_json.len() == 1 {
        sent_json[0].clone()
    } else {
        Value::Array(sent_json)
    })?;
    Ok(Exchange {
        request: RequestRecord {
            method: "POST".into(),
            url: t.url(),
            headers: t.metadata.clone(),
            body: req_body,
        },
        response: Some(ResponseRecord {
            status: code,
            http_version: "gRPC".into(),
            reason: code_name(code).into(),
            headers,
            size: body.len(),
            body,
        }),
        timing: Timing {
            total_ms: started.elapsed().as_secs_f64() * 1000.0,
            ..Default::default()
        },
        curl_exit: 0,
        error: None,
    })
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

/// Runs a `.grpc` request and records it in history.
pub fn run(project: &Project, curl: &Curl, rel: &Path, opts: &RunOptions) -> Result<RunResult> {
    let prepared = prepare(project, curl, rel, opts)?;
    let t = target(project, &prepared.spec, &prepared.ctx.values(&project.root))?;
    let raw = match runtime()?.block_on(call(project, &t)) {
        Ok(ex) => ex,
        Err(e)
            if format!("{e:#}").contains("Failed to connect")
                || format!("{e:#}").contains("transport error") =>
        {
            Exchange {
                request: RequestRecord {
                    method: "POST".into(),
                    url: t.url(),
                    headers: t.metadata.clone(),
                    body: vec![],
                },
                error: Some(format!("{e:#}")),
                ..Default::default()
            }
        }
        Err(e) => return Err(e),
    };
    finish(project, rel, prepared, raw, opts, None, vec![])
}

/// Services and their methods, for `curly grpc list`.
pub fn list(project: &Project, t: &Target) -> Result<Vec<(String, Vec<String>)>> {
    runtime()?.block_on(async {
        let channel = channel(project, t).await?;
        let (_, names) = descriptors(project, t, channel.clone(), &[], true).await?;
        let names: Vec<String> = names
            .into_iter()
            .filter(|n| !n.starts_with("grpc.reflection."))
            .collect();
        let (pool, _) = descriptors(project, t, channel, &names, false).await?;
        Ok(names
            .iter()
            .filter_map(|n| pool.get_service_by_name(n))
            .map(|s| {
                let methods = s
                    .methods()
                    .map(|m| {
                        format!(
                            "{}({}{}) returns ({}{})",
                            m.name(),
                            if m.is_client_streaming() {
                                "stream "
                            } else {
                                ""
                            },
                            m.input().full_name(),
                            if m.is_server_streaming() {
                                "stream "
                            } else {
                                ""
                            },
                            m.output().full_name()
                        )
                    })
                    .collect();
                (s.full_name().to_string(), methods)
            })
            .collect())
    })
}

/// Example JSON for a message type (one level of each nested message).
pub fn example(desc: &MessageDescriptor, depth: usize) -> Value {
    let mut out = serde_json::Map::new();
    for f in desc.fields() {
        let v = match f.kind() {
            Kind::Message(m) if depth < 3 => example(&m, depth + 1),
            Kind::Message(_) => json!({}),
            Kind::Enum(e) => json!(
                e.values()
                    .find(|v| v.number() != 0)
                    .or_else(|| e.values().next())
                    .map(|v| v.name().to_string())
                    .unwrap_or_default()
            ),
            Kind::String => json!("string"),
            Kind::Bytes => json!("aGVsbG8="),
            Kind::Bool => json!(true),
            Kind::Double | Kind::Float => json!(1.5),
            Kind::Int64 | Kind::Uint64 | Kind::Sint64 | Kind::Fixed64 | Kind::Sfixed64 => {
                json!("1")
            }
            _ => json!(1),
        };
        out.insert(
            f.json_name().to_string(),
            if f.is_list() { json!([v]) } else { v },
        );
    }
    Value::Object(out)
}

/// Describes a method: signature and example request, for `curly grpc describe`.
pub fn describe(project: &Project, t: &Target) -> Result<(String, Value)> {
    runtime()?.block_on(async {
        let channel = channel(project, t).await?;
        let (pool, _) =
            descriptors(project, t, channel, std::slice::from_ref(&t.service), false).await?;
        let m = method_descriptor(&pool, t)?;
        let mut text = format!(
            "rpc {}({}{}) returns ({}{})\n",
            m.full_name(),
            if m.is_client_streaming() {
                "stream "
            } else {
                ""
            },
            m.input().full_name(),
            if m.is_server_streaming() {
                "stream "
            } else {
                ""
            },
            m.output().full_name()
        );
        for (label, msg) in [("request", m.input()), ("response", m.output())] {
            text.push_str(&format!("\nmessage {} ({label}) {{\n", msg.full_name()));
            for f in msg.fields() {
                let ty = match f.kind() {
                    Kind::Message(x) => x.full_name().to_string(),
                    Kind::Enum(e) => e.full_name().to_string(),
                    other => format!("{other:?}").to_ascii_lowercase(),
                };
                text.push_str(&format!(
                    "  {}{ty} {} = {};\n",
                    if f.is_list() { "repeated " } else { "" },
                    f.name(),
                    f.number()
                ));
            }
            text.push_str("}\n");
        }
        Ok((text, example(&m.input(), 0)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls_and_codes() {
        assert_eq!(
            parse_url("grpc://h:1/a.B/C").unwrap(),
            GrpcUrl {
                tls: false,
                authority: "h:1".into(),
                method: Some(("a.B".into(), "C".into()))
            }
        );
        assert_eq!(
            parse_url("grpcs://h:443").unwrap(),
            GrpcUrl {
                tls: true,
                authority: "h:443".into(),
                method: None
            }
        );
        assert!(parse_url("http://h/a.B/C").is_err());
        assert_eq!(code_name(5), "NOT_FOUND");
        assert_eq!(code_from_name("unauthenticated"), Some(16));
        assert_eq!(code_from_name("nope"), None);
    }

    #[test]
    fn builds_targets_from_files() {
        let tmp = tempfile::tempdir().unwrap();
        crate::project::init(tmp.path(), &Default::default()).unwrap();
        let p = Project::load(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("req.json"), "{\"id\": 2}").unwrap();
        let text = "expand-url = \"grpc://{{T}}/pkg.Svc/Get\"\nexpand-header = \"Authorization: Bearer {{TOK}}\"\ndata = @req.json\ndata = \"{}\"\nproto = \"p/x.proto\"\nmax-time = 2\n";
        let spec = RequestSpec::from_config("x.grpc".into(), crate::curlconf::parse(text));
        let vars = BTreeMap::from([
            ("T".to_string(), "h:1".to_string()),
            ("TOK".to_string(), "abc".to_string()),
        ]);
        let t = target(&p, &spec, &vars).unwrap();
        assert_eq!(
            (t.authority.as_str(), t.service.as_str(), t.method.as_str()),
            ("h:1", "pkg.Svc", "Get")
        );
        assert_eq!(
            t.metadata,
            vec![("authorization".into(), "Bearer abc".into())]
        );
        assert_eq!(
            t.messages,
            vec!["{\"id\": 2}".to_string(), "{}".to_string()]
        );
        assert_eq!(t.protos, vec![PathBuf::from("p/x.proto")]);
        assert_eq!(t.timeout, Some(Duration::from_secs(2)));
        assert_eq!(t.url(), "grpc://h:1/pkg.Svc/Get");
        let bad = RequestSpec::from_config(
            "x.grpc".into(),
            crate::curlconf::parse("url = \"grpc://h:1/a.B/C\"\nlocation\n"),
        );
        assert!(
            target(&p, &bad, &vars)
                .unwrap_err()
                .to_string()
                .contains("`location` is not supported in .grpc files")
        );
    }
}
