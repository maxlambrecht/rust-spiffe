#![expect(missing_docs, reason = "example")]
#![expect(unused_crate_dependencies, reason = "used in the library target")]

use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_client, AllowList};
use spiffe_rustls_tokio::TlsConnector;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[expect(clippy::print_stdout, clippy::print_stderr, reason = "example")]
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

    // Use spiffe-rustls-tokio::TlsConnector which automatically extracts peer identity
    let connector = TlsConnector::new(Arc::new(client_cfg));

    // rustls requires a ServerName even though we authenticate via SPIFFE ID.
    // This is used for SNI (Server Name Indication) in the TLS handshake.
    // Certificate validation is based on SPIFFE ID, not hostname.
    let server_name = rustls::pki_types::ServerName::try_from("example.org")?;

    // Use connect_addr convenience method that combines TCP connect + TLS handshake
    match connector
        .connect_addr("127.0.0.1:8443".parse()?, server_name)
        .await
    {
        Ok((mut tls, peer_identity)) => {
            // Extract and display peer SPIFFE ID
            if let Some(spiffe_id) = peer_identity.spiffe_id() {
                println!("Connected to server (SPIFFE ID: {spiffe_id})");
            } else {
                println!("Connected to server (no SPIFFE ID)");
            }

            tls.write_all(b"ping\n").await?;

            let mut buf = [0u8; 1024];
            let n = tls.read(&mut buf).await?;
            #[expect(clippy::indexing_slicing, reason = "Read contract")]
            let msg = String::from_utf8_lossy(&buf[..n]);
            let msg = msg.trim_end();
            println!("client received: {msg}");

            let _unused: std::io::Result<()> = tls.shutdown().await;
        }
        Err(e) => {
            eprintln!("TLS connection failed: {e}");
            return Err(e.into());
        }
    }

    source.shutdown().await;
    Ok(())
}
