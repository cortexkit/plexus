//! A test's own client connection to an in-process subc daemon.

use std::time::Duration;

use subc_transport::authenticate_client;
use tokio::net::TcpStream;

/// Connect to the daemon's first endpoint and authenticate as a client.
pub async fn connect_client(connection: &subc_transport::ConnectionInfo) -> TcpStream {
    let endpoint = connection.endpoints.first().expect("daemon endpoint");
    let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
        .await
        .expect("connect daemon");
    authenticate_client(&mut stream, connection, Duration::from_secs(5))
        .await
        .expect("authenticate daemon client");
    stream
}
