use spiffe::X509Source;
use spiffe_rustls::{ServerConfigBuilder, ServerConfigOptions};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Env-driven, zero-config Workload API connection (SPIFFE_ENDPOINT_SOCKET).
    let source = X509Source::new().await?;

    // Server only accepts a specific client SPIFFE ID.
    // let opts = ServerConfigOptions {
    //     trust_domain: "example.org".try_into()?,
    //     authorize_client: Arc::new(|id: &str| id == "spiffe://example.org/myservice"),
    // };

    let opts = ServerConfigOptions::allow_any("example.org".try_into()?);

    let server_cfg = ServerConfigBuilder::new(source.clone(), opts).build()?;
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let addr = "127.0.0.1:8443";
    let listener = TcpListener::bind(addr).await?;
    println!("mTLS server listening on {addr}");

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
                                Ok(n) if n > 0 => {
                                    let msg = String::from_utf8_lossy(&buf[..n]).trim_end().to_string();
                                    println!("server received: {msg}");

                                    let reply = format!("hello from server (got: {msg})\n");
                                    let _ = tls.write_all(reply.as_bytes()).await;
                                    let _ = tls.shutdown().await;
                                }
                                Ok(_) => println!("server: client closed without sending data"),
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
