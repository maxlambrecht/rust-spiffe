use spiffe::X509Source;
use spiffe_rustls::{ServerConfigBuilder, ServerConfigOptions};
use tonic::{Request, Response, Status};
use tonic_rustls::Server;

pub mod helloworld {
    tonic::include_proto!("helloworld");
}

use helloworld::greeter_server::{Greeter, GreeterServer};
use helloworld::{HelloReply, HelloRequest};

#[derive(Default)]
struct MyGreeter;

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(&self, req: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> {
        let name = req.into_inner().name;
        Ok(Response::new(HelloReply {
            message: format!("hello, {name}"),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let socket = std::env::var("SPIFFE_ENDPOINT_SOCKET")
        .unwrap_or_else(|_| "unix:///tmp/spire-agent/public/api.sock".to_string());
    unsafe { std::env::set_var("SPIFFE_ENDPOINT_SOCKET", socket) };

    let source = X509Source::new().await?;

    let mut server_cfg = ServerConfigBuilder::new(
        source.clone(),
        ServerConfigOptions::allow_any("example.org".try_into()?),
    )
    .build()
    .await?;

    // gRPC requires HTTP/2 via ALPN.
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];

    let addr = "127.0.0.1:50051".parse()?;
    eprintln!("gRPC server listening on https://{addr}");

    let mut server = Server::builder().tls_config(server_cfg)?;

    server
        .add_service(GreeterServer::new(MyGreeter))
        .serve_with_shutdown(addr, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    let _ = source.shutdown().await;
    Ok(())
}
