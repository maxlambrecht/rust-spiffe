#![cfg(feature = "integration-tests")]

use std::net::SocketAddr;
use std::sync::Arc;

use spiffe::X509Source;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use spiffe_rustls::{
    ClientConfigBuilder, ClientConfigOptions, ServerConfigBuilder, ServerConfigOptions,
};

#[tokio::test]
async fn mtls_handshake_succeeds_with_spire() {
    let sock = "unix:///tmp/spire-agent/public/api.sock";
    unsafe {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", sock);
    }

    let source = X509Source::new().await.unwrap();

    let opts = ServerConfigOptions {
        trust_domain: "example.org".try_into()?,
        authorize_client: Arc::new(|id: &str| {
            id == "spiffe://example.org/myservice" || id == "spiffe://example.org/myservice2"
        }),
    };

    let server_cfg = ServerConfigBuilder::new(source.clone(), opts)
        .build()
        .await
        .unwrap();

    let client_cfg = ClientConfigBuilder::new(
        source.clone(),
        ClientConfigOptions::allow_any("example.org".try_into().unwrap()),
    )
    .build()
    .await
    .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _tls = acceptor.accept(tcp).await.unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("example.org").unwrap();
    let _tls = connector.connect(server_name, tcp).await.unwrap();

    server_task.await.unwrap();

    let _ = source.shutdown().await;
}
