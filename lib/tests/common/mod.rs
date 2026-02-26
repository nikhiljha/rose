use rose::config::{self, CertKeyPair};
use rose::transport::{QuicClient, QuicServer};
use std::net::SocketAddr;
use std::path::PathBuf;

pub struct MtlsFixture {
    pub server: QuicServer,
    pub client_cert: CertKeyPair,
    _auth_dir: PathBuf,
}

impl MtlsFixture {
    pub fn new() -> Self {
        let server_cert = config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();
        let client_cert = config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();

        let auth_dir = std::env::temp_dir().join(format!(
            "rose-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::fs::write(auth_dir.join("client.crt"), client_cert.cert_der.as_ref()).unwrap();

        let server =
            QuicServer::bind_mutual_tls("127.0.0.1:0".parse().unwrap(), server_cert, &auth_dir)
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

    pub async fn connect(&self, client: &QuicClient) -> quinn::Connection {
        client
            .connect_with_cert(
                self.addr(),
                "localhost",
                self.server.server_cert_der(),
                &self.client_cert,
            )
            .await
            .unwrap()
    }
}

impl Drop for MtlsFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._auth_dir);
    }
}
