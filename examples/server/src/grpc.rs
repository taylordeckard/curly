//! gRPC `curly.test.v1.UserService` with server reflection, backed by the
//! same users as the REST endpoints.

use std::pin::Pin;

use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

use crate::AppState;

/// Generated messages and service traits.
pub mod pb {
    #![allow(missing_docs)]
    tonic::include_proto!("curly.test.v1");
    /// Encoded descriptors (including imports) for server reflection.
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/users_descriptor.bin"));
}

use pb::user_service_server::UserService;
use pb::{
    ChatMessage, CreateUsersResponse, GetUserRequest, ListUsersRequest, NewUser, Role, User,
    WhoAmIResponse,
};

/// Service implementation.
pub struct Users {
    /// Shared server state.
    pub state: AppState,
}

fn to_pb(u: &crate::User) -> User {
    User {
        id: u.id as i64,
        name: u.name.clone(),
        email: u.email.clone(),
        role: if u.id == 1 {
            Role::Admin as i32
        } else {
            Role::Member as i32
        },
    }
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl UserService for Users {
    async fn get_user(&self, req: Request<GetUserRequest>) -> Result<Response<User>, Status> {
        let id = req.into_inner().id;
        let inner = self.state.inner.lock().expect("state lock");
        inner
            .users
            .get(&(id as u64))
            .map(|u| Response::new(to_pb(u)))
            .ok_or_else(|| Status::not_found(format!("user {id} not found")))
    }

    type ListUsersStream = BoxStream<User>;

    async fn list_users(
        &self,
        req: Request<ListUsersRequest>,
    ) -> Result<Response<Self::ListUsersStream>, Status> {
        let limit = req.into_inner().limit;
        let users: Vec<User> = {
            let inner = self.state.inner.lock().expect("state lock");
            inner
                .users
                .values()
                .take(if limit > 0 {
                    limit as usize
                } else {
                    usize::MAX
                })
                .map(to_pb)
                .collect()
        };
        Ok(Response::new(Box::pin(tokio_stream::iter(
            users.into_iter().map(Ok),
        ))))
    }

    async fn create_users(
        &self,
        req: Request<Streaming<NewUser>>,
    ) -> Result<Response<CreateUsersResponse>, Status> {
        let mut stream = req.into_inner();
        let mut ids = Vec::new();
        while let Some(new) = stream.message().await? {
            let mut inner = self.state.inner.lock().expect("state lock");
            inner.next_id += 1;
            let id = inner.next_id;
            inner.users.insert(
                id,
                crate::User {
                    id,
                    name: new.name,
                    email: new.email,
                },
            );
            ids.push(id as i64);
        }
        Ok(Response::new(CreateUsersResponse {
            created: ids.len() as i32,
            ids,
        }))
    }

    type ShoutStream = BoxStream<ChatMessage>;

    async fn shout(
        &self,
        req: Request<Streaming<ChatMessage>>,
    ) -> Result<Response<Self::ShoutStream>, Status> {
        let out = req.into_inner().map(|m| {
            m.map(|c| ChatMessage {
                text: c.text.to_uppercase(),
            })
        });
        Ok(Response::new(Box::pin(out)))
    }

    async fn who_am_i(&self, req: Request<()>) -> Result<Response<WhoAmIResponse>, Status> {
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default()
            .to_string();
        let ok = {
            let inner = self.state.inner.lock().expect("state lock");
            inner.tokens.contains(&token) || inner.oauth.access_token_valid(&token)
        };
        if ok {
            Ok(Response::new(WhoAmIResponse {
                username: "demo".into(),
            }))
        } else {
            Err(Status::unauthenticated("missing or invalid token"))
        }
    }
}

/// Serves gRPC (with reflection) on `listener` until `shutdown` resolves.
pub async fn serve(
    state: AppState,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), tonic::transport::Error> {
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(pb::FILE_DESCRIPTOR_SET)
        .build_v1()
        .expect("reflection service");
    tonic::transport::Server::builder()
        .add_service(pb::user_service_server::UserServiceServer::new(Users {
            state,
        }))
        .add_service(reflection)
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            shutdown,
        )
        .await
}
