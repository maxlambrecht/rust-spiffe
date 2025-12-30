#![cfg(feature = "integration-tests")]

use rustls::pki_types::ServerName;
use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_client, mtls_server};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn integration_mtls() -> Result<(), Box<dyn std::error::Error>> {
    let source = X509Source::new().await?;

    let server_cfg = mtls_server(source.clone())
        .authorize(authorizer::any())
        .build()?;

    let client_cfg = mtls_client(source.clone())
        .authorize(authorizer::any())
        .build()?;

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // server task
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _tls = acceptor.accept(tcp).await.unwrap();
    });

    // client
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("example.org")?;
    let _tls = connector.connect(server_name, tcp).await?;

    server.await?;
    source.shutdown().await;
    Ok(())
}
