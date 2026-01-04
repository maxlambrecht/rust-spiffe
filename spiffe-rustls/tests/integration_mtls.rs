use rustls::pki_types::ServerName;
use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_client, mtls_server, Authorizer};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Clone, Copy, Debug)]
enum Expected {
    Success,
    ClientConnectFails,
    ServerAcceptFails,
}

#[derive(Clone, Copy, Debug)]
enum Authz {
    Any,
    DenyAll,
    ExactAllowedIds,
}

#[derive(Clone, Debug)]
struct Case {
    name: &'static str,
    client_authz: Authz,
    server_authz: Authz,
    expected: Expected,
}

#[tokio::test]
#[ignore = "requires running SPIFFE Workload API"]
async fn integration_mtls_matrix() -> Result<(), Box<dyn std::error::Error>> {
    let allowed_ids = [
        "spiffe://example.org/myservice",
        "spiffe://example.org/myservice2",
    ];

    let cases = [
        Case {
            name: "ok: both sides authorize",
            client_authz: Authz::Any,
            server_authz: Authz::Any,
            expected: Expected::Success,
        },
        Case {
            name: "reject: client rejects server",
            client_authz: Authz::DenyAll,
            server_authz: Authz::Any,
            expected: Expected::ClientConnectFails,
        },
        Case {
            name: "reject: server rejects client",
            client_authz: Authz::Any,
            server_authz: Authz::DenyAll,
            expected: Expected::ServerAcceptFails,
        },
        Case {
            name: "reject: both reject",
            client_authz: Authz::DenyAll,
            server_authz: Authz::DenyAll,
            expected: Expected::ClientConnectFails,
        },
        Case {
            name: "ok: exact SPIFFE ID allow-list on both ends",
            client_authz: Authz::ExactAllowedIds,
            server_authz: Authz::ExactAllowedIds,
            expected: Expected::Success,
        },
    ];

    for case in cases {
        run_case(case, allowed_ids).await?;
    }

    Ok(())
}

async fn run_case(
    case: Case,
    allowed_ids: [&'static str; 2],
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("--- case: {} ---", case.name);

    let source = X509Source::new().await?;

    let server_auth = make_authorizer(case.server_authz, allowed_ids)?;
    let client_auth = make_authorizer(case.client_authz, allowed_ids)?;

    let server_cfg = mtls_server(source.clone()).authorize(server_auth).build()?;
    let client_cfg = mtls_client(source.clone()).authorize(client_auth).build()?;

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Server: accept exactly one connection and report whether TLS accept succeeded.
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let res = acceptor.accept(tcp).await;
        res.map(|_| ())
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
    });

    // Client: connect + TLS connect and capture result.
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("example.org")?;
    let client_res = connector.connect(server_name, tcp).await;

    let server_res = server_task.await.expect("server task panicked");

    match case.expected {
        Expected::Success => {
            if let Err(e) = client_res {
                panic!(
                    "case '{}' expected client success, got error: {e:?}",
                    case.name
                );
            }
            if let Err(e) = server_res {
                panic!(
                    "case '{}' expected server success, got error: {e:?}",
                    case.name
                );
            }
        }

        Expected::ClientConnectFails => {
            if client_res.is_ok() {
                panic!("case '{}' expected client failure, got success", case.name);
            }
        }

        Expected::ServerAcceptFails => {
            if server_res.is_ok() {
                panic!("case '{}' expected server failure, got success", case.name);
            }
        }
    }

    source.shutdown().await;
    Ok(())
}

#[derive(Clone)]
enum TestAuthorizer {
    Any(authorizer::Any),
    DenyAll,
    Exact(authorizer::Exact),
}

impl Authorizer for TestAuthorizer {
    fn authorize(&self, peer: &spiffe::SpiffeId) -> bool {
        match self {
            Self::Any(a) => a.authorize(peer),
            Self::DenyAll => false,
            Self::Exact(a) => a.authorize(peer),
        }
    }
}

fn make_authorizer(
    mode: Authz,
    allowed_ids: [&'static str; 2],
) -> Result<TestAuthorizer, Box<dyn std::error::Error>> {
    Ok(match mode {
        Authz::Any => TestAuthorizer::Any(authorizer::any()),
        Authz::DenyAll => TestAuthorizer::DenyAll,
        Authz::ExactAllowedIds => TestAuthorizer::Exact(authorizer::exact(allowed_ids)?),
    })
}
