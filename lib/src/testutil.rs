#![cfg_attr(coverage_nightly, coverage(off))]

use std::net::SocketAddr;

use quinn::Connection;
use rustls::pki_types::CertificateDer;

use crate::config::{self, CertKeyPair};
use crate::transport::{QuicClient, QuicServer};

pub struct MtlsFixture {
    pub server: QuicServer,
    pub client_cert: CertKeyPair,
    _auth_dir: tempfile::TempDir,
}

impl MtlsFixture {
    pub fn new() -> Self {
        let server_cert = config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();
        let client_cert = config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();

        let auth_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            auth_dir.path().join("client.crt"),
            client_cert.cert_der.as_ref(),
        )
        .unwrap();

        let server = QuicServer::bind_mutual_tls(
            "127.0.0.1:0".parse().unwrap(),
            server_cert,
            auth_dir.path(),
        )
        .unwrap();

        Self {
            server,
            client_cert,
            _auth_dir: auth_dir,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.server.local_addr().unwrap()
    }

    pub fn server_cert_der(&self) -> &CertificateDer<'static> {
        self.server.server_cert_der()
    }

    pub async fn connect(&self, client: &QuicClient) -> Connection {
        client
            .connect_with_cert(
                self.addr(),
                "localhost",
                self.server_cert_der(),
                &self.client_cert,
            )
            .await
            .unwrap()
    }
}

pub async fn connected_pair() -> (Connection, Connection, MtlsFixture, QuicClient) {
    let fixture = MtlsFixture::new();

    let accept = tokio::spawn({
        let endpoint = fixture.server.endpoint.clone();
        async move {
            let incoming = endpoint.accept().await.unwrap();
            incoming.await.unwrap()
        }
    });

    let client = QuicClient::new().unwrap();
    let client_conn = fixture.connect(&client).await;
    let server_conn = accept.await.unwrap();

    (client_conn, server_conn, fixture, client)
}
