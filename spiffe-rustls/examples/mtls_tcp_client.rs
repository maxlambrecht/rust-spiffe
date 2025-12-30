use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_client, AllowList};
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Env-driven, zero-config Workload API connection (SPIFFE_ENDPOINT_SOCKET).
    let source = X509Source::new().await?;

    // Example 1: Authorization by exact SPIFFE IDs
    // Only accept connections to servers with these specific SPIFFE IDs.
    // Pass string literals directly - exact() will convert them.
    let allowed_server_ids = [
        "spiffe://example.org/myservice",
        "spiffe://example.org/myservice2",
    ];

    // Example 2: Trust Domain Policy (defense-in-depth)
    // Restrict which trust domains are accepted, even if the Workload API
    // provides bundles for multiple trust domains (federation scenario).
    // This is a defense-in-depth mechanism - the primary trust comes from
    // the bundle set, but this policy adds an additional restriction.
    let mut allowed_trust_domains = BTreeSet::new();
    allowed_trust_domains.insert("example.org".try_into()?);
    // In a federation scenario, you might also allow:
    // allowed_trust_domains.insert("broker.example".try_into()?);
    // allowed_trust_domains.insert("stockmarket.example".try_into()?);

    // Build rustls client config with:
    // - Authorization: only accept servers with the specified SPIFFE IDs
    // - Trust Domain Policy: only trust certificates from the allowed trust domains
    let client_cfg = mtls_client(source.clone())
        .authorize(authorizer::exact(allowed_server_ids)?)
        .trust_domain_policy(AllowList(allowed_trust_domains))
        .build()?;
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

    source.shutdown().await;
    Ok(())
}
