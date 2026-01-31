#![expect(missing_docs, reason = "example")]
#![expect(unused_crate_dependencies, reason = "used in the library target")]

use spiffe::{TrustDomain, X509Source};
use spiffe_rustls::{authorizer, mtls_server, LocalOnly};
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[expect(clippy::print_stdout, clippy::print_stderr, reason = "example")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Env-driven, zero-config Workload API connection (SPIFFE_ENDPOINT_SOCKET).
    let source = X509Source::new().await?;

    // Example 1: Authorization by trust domain
    // Accept clients from any SPIFFE ID in the specified trust domains.
    // This is more flexible than exact SPIFFE ID matching and works well
    // when you trust an entire trust domain.
    // Pass string literals directly - trust_domains() will convert them.
    let allowed_trust_domains = [
        "example.org",
        // In a federation scenario, you might also allow:
        // "broker.example",
    ];

    // Example 2: Trust Domain Policy - LocalOnly
    // Only trust certificates from a single trust domain, even if the Workload API
    // provides bundles for multiple trust domains (federation scenario).
    // This is the most restrictive policy and ensures we only accept connections
    // from our own trust domain.
    let local_trust_domain: TrustDomain = "example.org".try_into()?;

    // Build rustls server config with:
    // - Authorization: accept clients from the specified trust domains
    // - Trust Domain Policy: only trust certificates from our local trust domain
    //   (defense-in-depth: even if federation provides other bundles, we ignore them)
    let server_cfg = mtls_server(source.clone())
        .authorize(authorizer::trust_domains(allowed_trust_domains)?)
        .trust_domain_policy(LocalOnly(local_trust_domain))
        .build()?;
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let addr = "127.0.0.1:8443";
    let listener = TcpListener::bind(addr).await?;
    eprintln!("mTLS server listening on tcp://{addr}");
    eprintln!("Server configured to:");
    eprintln!("  - Accept clients from trust domains: example.org");
    eprintln!("  - Trust domain policy: LocalOnly (example.org)");

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (tcp, peer) = res?;
                let acceptor = acceptor.clone();

                tokio::spawn(async move {
                    match acceptor.accept(tcp).await {
                        Ok(mut tls) => {
                            println!("TLS handshake OK from {peer}");

                            let mut buf = [0u8; 1024];
                            match tls.read(&mut buf).await {
                                Ok(n) => {
                                    if n == 0 {
                                        println!("server: client closed without sending data");
                                    } else {
                                        #[expect(clippy::indexing_slicing, reason = "Read contract")]
                                        let msg = String::from_utf8_lossy(&buf[..n]);
                                        let msg = msg.trim_end();
                                        println!("server received: {msg}");
                                        let reply = format!("hello from server (got: {msg})\n");
                                        let _unused: std::io::Result<()> = tls.write_all(reply.as_bytes()).await;
                                        let _unused: std::io::Result<()> = tls.shutdown().await;
                                    }
                                }
                                Err(e) => eprintln!("server read error: {e}"),
                            }
                        }
                        Err(e) => eprintln!("TLS handshake failed from {peer}: {e}"),
                    }
                });
            }

            _ = tokio::signal::ctrl_c() => {
                println!("shutdown requested");
                break;
            }
        }
    }

    source.shutdown().await;
    Ok(())
}
