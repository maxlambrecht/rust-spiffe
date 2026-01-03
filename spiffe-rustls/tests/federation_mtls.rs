use rustls::pki_types::ServerName;
use spiffe::{TrustDomain, X509Source};
use spiffe_rustls::{authorizer, mtls_client, mtls_server, Authorizer};
use std::env;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn env_var(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("missing required env var: {name}").into())
}

/// Federation cross-trust-domain handshake.
///
/// Preconditions:
/// - A Workload API for `example.org` is running and reachable via `SPIFFE_ENDPOINT_SOCKET`.
/// - A Workload API for `example-federated.org` is running and reachable via `SPIFFE_ENDPOINT_SOCKET_FEDERATED`.
/// - Federation is established such that each side receives the other's bundle in its bundle set.
/// - Each agent has an entry that matches the running test process (selector unix:uid:<id -u>),
///   so the process can obtain an X.509 SVID from each trust domain.
#[tokio::test]
#[ignore = "requires two running SPIFFE Workload API endpoints (primary + federated)"]
async fn integration_mtls_federation_cross_trust_domain() -> Result<(), Box<dyn std::error::Error>>
{
    // Primary agent socket (example.org)
    let primary_socket = env_var("SPIFFE_ENDPOINT_SOCKET")?;

    // Federated agent socket (example-federated.org)
    let federated_socket = env_var("SPIFFE_ENDPOINT_SOCKET_FEDERATED")?;

    let primary = X509Source::builder()
        .endpoint(primary_socket)
        .build()
        .await?;

    let federated = X509Source::builder()
        .endpoint(federated_socket)
        .build()
        .await?;

    {
        let td_primary: TrustDomain = "example.org".try_into()?;
        let td_federated: TrustDomain = "example-federated.org".try_into()?;

        let p = primary.x509_context()?;
        let f = federated.x509_context()?;

        if p.bundle_set().get(&td_federated).is_none() {
            return Err(
                "primary bundle set missing example-federated.org (federation not established)"
                    .into(),
            );
        }
        if f.bundle_set().get(&td_primary).is_none() {
            return Err(
                "federated bundle set missing example.org (federation not established)".into(),
            );
        }
    }

    // Authorization: verify the peer is in the expected trust domain.
    let server_auth: Arc<dyn Authorizer> = Arc::new(authorizer::trust_domains(["example.org"])?);
    let client_auth: Arc<dyn Authorizer> =
        Arc::new(authorizer::trust_domains(["example-federated.org"])?);

    let server_cfg = mtls_server(federated.clone())
        .authorize(server_auth)
        .build()?;

    let client_cfg = mtls_client(primary.clone())
        .authorize(client_auth)
        .build()?;

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Server: accept exactly one connection; handshake must succeed.
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        acceptor
            .accept(tcp)
            .await
            .map(|_tls| ())
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
    });

    // Client: connect + handshake must succeed.
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("example.org")?;
    let client_res = connector.connect(server_name, tcp).await;

    let server_res = server_task.await.expect("server task panicked");

    if let Err(e) = client_res {
        return Err(format!("client handshake failed: {e:?}").into());
    }
    if let Err(e) = server_res {
        return Err(format!("server accept failed: {e:?}").into());
    }

    primary.shutdown().await;
    federated.shutdown().await;

    Ok(())
}
