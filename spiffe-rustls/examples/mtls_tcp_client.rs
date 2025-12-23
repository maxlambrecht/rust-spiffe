use spiffe::X509Source;
use spiffe_rustls::{ClientConfigBuilder, ClientConfigOptions};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Env-driven, zero-config Workload API connection (SPIFFE_ENDPOINT_SOCKET).
    let source = X509Source::new().await?;

    // Client only accepts specific server SPIFFE IDs.
    let opts = ClientConfigOptions {
        trust_domain: "example.org".try_into()?,
        authorize_server: Arc::new(|id: &str| {
            id == "spiffe://example.org/myservice" || id == "spiffe://example.org/myservice2"
        }),
    };

    let client_cfg = ClientConfigBuilder::new(source.clone(), opts)
        .build()
        .await?;
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let tcp = TcpStream::connect("127.0.0.1:8443").await?;

    // rustls requires a ServerName even though we authenticate via SPIFFE ID.
    let server_name = rustls::pki_types::ServerName::try_from("example.org")?;
    let mut tls = connector.connect(server_name, tcp).await?;

    tls.write_all(b"ping\n").await?;

    let mut buf = [0u8; 1024];
    let n = tls.read(&mut buf).await?;
    println!(
        "client received: {}",
        String::from_utf8_lossy(&buf[..n]).trim_end()
    );

    let _ = tls.shutdown().await;

    source.shutdown().await?;
    Ok(())
}
