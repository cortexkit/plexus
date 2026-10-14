//! The HTTP request reader the transport test mocks share.
//!
//! `mcp_remote` and `rest_api` each stand up a throwaway TCP server to test
//! their client against, and both carried the same 26-line read loop -- the
//! copies differed only in the label inside a panic message.
//!
//! Kept here rather than in either module because neither owns it, and because a
//! reader living beside one transport invites the next person to fix it there
//! and leave the other behind. The conformance crate has its own copy of the
//! same logic for the same reason, and cannot share this one: `#[cfg(test)]`
//! code does not cross a crate boundary, and exporting it would mean a public
//! surface on `plexus-core` existing purely for another crate's tests.
//!
//! Test-only, so nothing here reaches a release binary.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[path = "../tests/support/http_server.rs"]
mod fixed;
pub(crate) use crate::bounded;
pub(crate) use fixed::FixedRequestServer;

/// Read one HTTP request from the stream, headers and body.
///
/// The loop exists because a body may span TCP segments: reading once returns
/// whatever the first segment held, which for a small request is everything and
/// for a larger one is a truncated body. A mock that answered on the first chunk
/// would fail intermittently and would look like a client defect rather than a
/// harness one.
///
/// `label` names the mock in the panic message, so a failure says which of the
/// two servers could not read rather than only that one of them could not.
pub(crate) fn read_mock_request(stream: &mut TcpStream, label: &str) -> Option<String> {
    let bytes = read_request_bytes(stream)
        .unwrap_or_else(|error| panic!("read mock {label} request: {error}"));
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The read loop behind `read_mock_request`, returning the I/O error instead
/// of panicking. Returns whatever arrived before end of stream, which is empty
/// when the client closed the connection without sending anything.
fn read_request_bytes(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes
            .windows(4)
            .position(|window| window == [13, 10, 13, 10])
        {
            let body_start = position + 4;
            let header_text = String::from_utf8_lossy(&bytes[..body_start]);
            // Case-insensitive: the header name is not case-sensitive on the
            // wire, and a client sending `content-length` must not be read as
            // sending no body at all.
            let content_length = header_text
                .lines()
                .find_map(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= body_start + content_length {
                break;
            }
        }
    }
    Ok(bytes)
}

/// A mock vendor with a keep-alive timeout, which always wins the race against
/// a client that reuses a connection idle for longer than that timeout.
///
/// Each accepted connection is kept open between requests (HTTP/1.1
/// keep-alive) and every request is answered normally, except one that arrives
/// after the connection sat idle for longer than `keep_alive`. That request is
/// read in full and the connection is then closed without an answer. This is
/// the losing side of the race a real server produces when it closes an idle
/// connection at its keep-alive timeout just as the client writes a request
/// onto it: the request has been sent, and the client sees "connection closed
/// before message completed". It is decided by idle time rather than timing
/// luck, so a client that drops idle connections sooner than `keep_alive`
/// always gets an answer and one that keeps them longer never does.
///
/// Stopping the server joins only the acceptor. Connection threads end when
/// the client closes its side, which happens when the client is dropped.
pub(crate) struct KeepAliveServer {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    acceptor: Option<JoinHandle<()>>,
}

impl KeepAliveServer {
    /// Start serving on an ephemeral local port. `respond` turns the raw
    /// request text into a raw HTTP response, which must NOT ask to close the
    /// connection (no `Connection: close`) and must carry a `Content-Length`.
    pub(crate) fn start<F>(keep_alive: Duration, respond: F) -> Self
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind keep-alive server");
        let address = listener.local_addr().expect("keep-alive server address");
        // Non-blocking so the acceptor can notice `stop` instead of waiting
        // forever for a connection that will never come.
        listener
            .set_nonblocking(true)
            .expect("make the keep-alive listener non-blocking");
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let respond = Arc::new(respond);
        let acceptor = {
            let connections = Arc::clone(&connections);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            connections.fetch_add(1, Ordering::SeqCst);
                            let respond = Arc::clone(&respond);
                            std::thread::spawn(move || {
                                serve_keep_alive(stream, keep_alive, respond.as_ref())
                            });
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Self {
            address,
            connections,
            stop,
            acceptor: Some(acceptor),
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// How many TCP connections the server has accepted so far.
    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for KeepAliveServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
    }
}

fn serve_keep_alive(mut stream: TcpStream, keep_alive: Duration, respond: &dyn Fn(&str) -> String) {
    // An accepted socket may inherit the listener's non-blocking mode on some
    // platforms; this connection's reads must block.
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let mut idle_since = Instant::now();
    loop {
        let request = match read_request_bytes(&mut stream) {
            Ok(bytes) if !bytes.is_empty() => bytes,
            // The client closed its side, typically because it dropped the
            // idle connection from its pool.
            _ => return,
        };
        if idle_since.elapsed() > keep_alive {
            // The request was read in full, so it was sent; returning drops
            // the stream and closes the connection without an answer.
            return;
        }
        let response = respond(&String::from_utf8_lossy(&request));
        if stream.write_all(response.as_bytes()).is_err() {
            return;
        }
        idle_since = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// A body arriving in a SECOND segment is still read whole.
    ///
    /// The only reason the loop exists, and nothing else exercises it: every
    /// request the transport tests send fits in one segment, so a simplification
    /// to "read once, return" would pass the entire suite while truncating any
    /// request that happens to split. The resulting failure would be
    /// intermittent and would present as a transport-client defect rather than a
    /// mock one, which is the expensive way to find it.
    ///
    /// The write is paused between header and body to force the split rather
    /// than hoping for one.
    #[test]
    fn a_body_split_across_segments_is_read_whole() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let body = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;

        let sender = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            write!(
                stream,
                "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .expect("write headers");
            stream.flush().expect("flush headers");
            std::thread::sleep(std::time::Duration::from_millis(120));
            stream.write_all(body.as_bytes()).expect("write body");
            stream.flush().expect("flush body");
        });

        let (mut accepted, _) = listener.accept().expect("accept");
        let request = read_mock_request(&mut accepted, "split").expect("read the request");
        sender.join().expect("sender finishes");

        assert!(
            request.ends_with(body),
            "the delayed body must be present in full: {request:?}"
        );
    }
}
