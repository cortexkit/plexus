//! The HTTP framing both stub servers share.
//!
//! The MCP and REST stubs differ entirely in what they SERVE -- one answers a
//! JSON-RPC tool protocol, the other matches routes and gates credentials --
//! but they speak the same transport underneath, and both carried
//! byte-identical copies of the request reader and the response formatter.
//!
//! Extracted because the duplication was in the framing rather than in the
//! behaviour: a fix to the reader landing in one copy and not the other would
//! give the two harnesses different ideas of what a well-formed request is, and
//! the surviving copy would keep accepting requests the fixed reader refused.
//!
//! Framing and the bounded worker lifecycle are shared. Request dispatch,
//! route matching and credential gates stay in the transport-specific servers.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The largest request a stub will buffer. Conformance requests are a few
/// kilobytes; the cap keeps a misbehaving client from growing a stub's buffer
/// without bound.
pub(crate) const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// A bounded local HTTP stub. Fixed workers serve connections synchronously,
/// so slow clients cannot create an unbounded number of detached threads.
pub(crate) struct StubHttpServer {
    endpoint: String,
    running: Arc<AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
    acceptor: Option<std::thread::JoinHandle<()>>,
    address: std::net::SocketAddr,
}

impl StubHttpServer {
    pub(crate) fn start(
        path: &str,
        response: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let endpoint = format!("http://{address}{path}");
        let running = Arc::new(AtomicBool::new(true));
        let response = Arc::new(response);
        let (sender, receiver) = std::sync::mpsc::sync_channel::<TcpStream>(4);
        let receiver = Arc::new(std::sync::Mutex::new(receiver));
        let workers = (0..4)
            .map(|_| {
                let receiver = Arc::clone(&receiver);
                let response = Arc::clone(&response);
                let running = Arc::clone(&running);
                std::thread::spawn(move || loop {
                    let stream = receiver.lock().unwrap().recv();
                    let Ok(stream) = stream else {
                        break;
                    };
                    if !running.load(Ordering::Acquire) {
                        break;
                    }
                    if let Err(error) = serve_connection(stream, &*response) {
                        eprintln!("stub HTTP connection failed: {error}");
                    }
                })
            })
            .collect();
        let accepting = Arc::clone(&running);
        let acceptor = std::thread::spawn(move || {
            accept_until_stopped(
                &accepting,
                || listener.accept().map(|(stream, _)| stream),
                |stream| {
                    if let Err(std::sync::mpsc::TrySendError::Full(mut stream)) =
                        sender.try_send(stream)
                    {
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                        let _ = stream.write_all(http_empty(503).as_bytes());
                    }
                },
            );
        });
        Ok(Self {
            endpoint,
            running,
            workers,
            acceptor: Some(acceptor),
            address,
        })
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Drop for StubHttpServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn serve_connection(
    mut stream: TcpStream,
    response: &impl Fn(&str) -> String,
) -> Result<(), String> {
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let request = match read_http_request(&mut DeadlineReader {
        stream: &mut stream,
        deadline,
    }) {
        Ok(request) => request,
        Err(error) => {
            let status = if error.contains("exceeds") { 413 } else { 400 };
            let _ =
                stream.write_all(http_json(status, r#"{"error":"invalid_request"}"#).as_bytes());
            return Err(error);
        }
    };
    stream
        .write_all(response(&request).as_bytes())
        .map_err(|error| error.to_string())
}

/// Read one HTTP request from the stream, headers and body.
///
/// Reads until the header terminator, then keeps reading until the declared
/// body has arrived -- a single read is not enough because a body may span TCP
/// segments, and a stub answering on the first chunk would intermittently see a
/// truncated request under load. The body length comes from `Content-Length`,
/// or from the chunk framing when the request is sent with
/// `Transfer-Encoding: chunked`; a chunked body is returned DECODED, after the
/// headers, so the stubs read the same JSON whichever framing the client chose.
///
/// The header terminator is searched for only in newly arrived bytes, so a
/// large request is not re-scanned from the start on every read, and a request
/// over [`MAX_REQUEST_BYTES`] is refused.
///
/// Incomplete requests are errors, never raw framing or partial JSON.
pub(crate) fn read_http_request(stream: &mut impl Read) -> Result<String, String> {
    read_http_request_until(stream, Instant::now() + Duration::from_secs(5))
}

struct DeadlineReader<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}
impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline exceeded")
            })?;
        self.stream
            .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))?;
        self.stream.read(buffer)
    }
}

fn read_http_request_until(stream: &mut impl Read, deadline: Instant) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let mut body_start: Option<usize> = None;
    let mut framing = Framing::Length(0);
    let mut chunked_cursor = 0;
    let mut chunked_body = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err("request deadline exceeded".into());
        }
        let read = match stream.read(&mut chunk) {
            Ok(0) => return Err("incomplete HTTP request".into()),
            Ok(count) => count,
            Err(error) => return Err(error.to_string()),
        };
        // Only the last three bytes already held can begin a terminator that
        // the new bytes complete.
        let search_from = bytes.len().saturating_sub(3);
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(format!(
                "request exceeds the {MAX_REQUEST_BYTES} byte stub limit"
            ));
        }
        let start = match body_start {
            Some(start) => start,
            None => {
                let Some(position) = find(&bytes[search_from..], b"\r\n\r\n") else {
                    continue;
                };
                let start = search_from + position + 4;
                framing = framing_of(&String::from_utf8_lossy(&bytes[..start]))?;
                body_start = Some(start);
                start
            }
        };
        match framing {
            Framing::Length(length) => {
                if bytes.len() >= start + length {
                    bytes.truncate(start + length);
                    return Ok(String::from_utf8_lossy(&bytes).into_owned());
                }
            }
            Framing::Chunked => {
                if decode_chunks(&bytes[start..], &mut chunked_cursor, &mut chunked_body)? {
                    let mut request = bytes[..start].to_vec();
                    request.extend_from_slice(&chunked_body);
                    return Ok(String::from_utf8_lossy(&request).into_owned());
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Framing {
    Length(usize),
    Chunked,
}

/// How the body after these headers is delimited. Header names are matched
/// case-insensitively: a client sending `content-length` must not be read as
/// sending no body at all. Chunked framing wins over a length, as HTTP/1.1
/// requires when both are present.
fn framing_of(headers: &str) -> Result<Framing, String> {
    let mut length = 0;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding"
            && value
                .split(',')
                .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
        {
            return Ok(Framing::Chunked);
        }
        if name == "content-length" {
            length = value
                .parse::<usize>()
                .map_err(|_| format!("malformed Content-Length {value:?}"))?;
            if length > MAX_REQUEST_BYTES {
                return Err(format!(
                    "declared body of {length} bytes exceeds the {MAX_REQUEST_BYTES} byte stub limit"
                ));
            }
        }
    }
    Ok(Framing::Length(length))
}

/// Decode as many complete chunks of `data` as have arrived, starting at
/// `cursor` and appending their payload to `body`. Returns true once the final
/// zero-size chunk and its trailer section are complete.
fn decode_chunks(data: &[u8], cursor: &mut usize, body: &mut Vec<u8>) -> Result<bool, String> {
    loop {
        let rest = &data[*cursor..];
        let Some(line_end) = find(rest, b"\r\n") else {
            return Ok(false);
        };
        let size_line = String::from_utf8_lossy(&rest[..line_end]);
        // Chunk extensions follow a ';' and carry nothing a stub needs.
        let size_text = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| format!("malformed chunk size {size_line:?}"))?;
        let data_start = line_end + 2;
        if size == 0 {
            // The trailer section ends at the first empty line.
            let trailers = &rest[data_start..];
            if trailers.starts_with(b"\r\n") {
                *cursor += data_start + 2;
                return Ok(true);
            }
            return match find(trailers, b"\r\n\r\n") {
                Some(end) => {
                    *cursor += data_start + end + 4;
                    Ok(true)
                }
                None => Ok(false),
            };
        }
        let data_end = data_start
            .checked_add(size)
            .filter(|end| *end <= MAX_REQUEST_BYTES)
            .ok_or_else(|| format!("chunk of {size} bytes exceeds the stub limit"))?;
        if rest.len() < data_end + 2 {
            return Ok(false);
        }
        if &rest[data_end..data_end + 2] != b"\r\n" {
            return Err("chunk data is not followed by CRLF".to_string());
        }
        body.extend_from_slice(&rest[data_start..data_end]);
        *cursor += data_end + 2;
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Run a stub's accept loop until `running` is cleared.
///
/// Every accept error other than "nothing waiting" is treated as transient: a
/// client that resets before the accept completes, or a moment of descriptor
/// exhaustion under parallel fixtures, must not end the stub. Breaking out on
/// such an error would leave a handle that still reports its endpoint while
/// nothing answers there, so every later request in the run would fail for a
/// reason unrelated to the code under test.
pub(crate) fn accept_until_stopped<S>(
    running: &AtomicBool,
    mut accept: impl FnMut() -> std::io::Result<S>,
    mut handle: impl FnMut(S),
) {
    while running.load(Ordering::Acquire) {
        match accept() {
            Ok(stream) if running.load(Ordering::Acquire) => handle(stream),
            Ok(_) => break,
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// Format a JSON response with `Connection: close`.
///
/// The stubs serve one request per connection, so closing is what lets a client
/// reading to EOF terminate rather than waiting on a keep-alive that will never
/// carry another request.
pub(crate) fn http_json(status: u16, body: &str) -> String {
    let crlf = "\r\n";
    format!(
        "HTTP/1.1 {status} {crlf}Content-Type: application/json{crlf}Content-Length: {}{crlf}Connection: close{crlf}{crlf}{body}",
        body.len()
    )
}

/// Format a response with no body.
pub(crate) fn http_empty(status: u16) -> String {
    let crlf = "\r\n";
    format!("HTTP/1.1 {status} {crlf}Content-Length: 0{crlf}Connection: close{crlf}{crlf}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn progress_does_not_extend_the_request_deadline() {
        struct Trickle(usize);
        impl Read for Trickle {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 20 {
                    return Ok(0);
                }
                self.0 += 1;
                std::thread::sleep(Duration::from_millis(2));
                buffer[0] = b'x';
                Ok(1)
            }
        }
        let error =
            read_http_request_until(&mut Trickle(0), Instant::now() + Duration::from_millis(10))
                .unwrap_err();
        assert!(
            error.contains("deadline"),
            "progress must not reset the overall deadline: {error}"
        );
    }

    #[test]
    fn incomplete_framing_is_refused_and_malformed_requests_get_http_errors() {
        for raw in [
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhi".as_slice(),
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n",
        ] {
            assert!(
                read_http_request(&mut std::io::Cursor::new(raw)).is_err(),
                "truncated bodies must be errors"
            );
        }
        let server = StubHttpServer::start("", |_| http_empty(204)).unwrap();
        for (length, status) in [
            ("bad".to_owned(), 400),
            ((MAX_REQUEST_BYTES + 1).to_string(), 413),
        ] {
            let mut stream = TcpStream::connect(server.address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            write!(
                stream,
                "POST / HTTP/1.1\r\nContent-Length: {length}\r\n\r\n"
            )
            .unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            assert!(
                reply.starts_with(&format!("HTTP/1.1 {status}")),
                "malformed request must receive HTTP {status}: {reply}"
            );
        }
    }

    #[test]
    fn stub_connections_use_a_fixed_worker_pool() {
        let server = StubHttpServer::start("", |_| http_empty(204)).unwrap();
        assert_eq!(server.workers.len(), 4, "stub workers must be bounded");
    }

    #[test]
    fn status_lines_include_the_reason_separator() {
        for response in [http_json(200, "{}"), http_empty(204)] {
            let line = response.lines().next().unwrap();
            assert!(
                line.splitn(3, ' ').count() == 3,
                "HTTP status must include a reason separator"
            );
        }
    }

    /// A body arriving in a SECOND segment is still read whole.
    ///
    /// This is the only reason the read loop exists, and no conformance fixture
    /// reaches it: measured by breaking the `Content-Length` check outright and
    /// watching both stub-backed fixtures still pass, because their requests fit
    /// in one segment. So without this test the loop is unexercised, and a
    /// future simplification to "read once, return" would look correct against
    /// the whole suite while truncating any request that happens to split.
    ///
    /// A split is not exotic -- it is what a larger payload or a slower client
    /// produces -- and the resulting failure would be intermittent and would
    /// present as a vendor problem rather than a harness one.
    ///
    /// The write is deliberately paused between header and body to force the
    /// split rather than hoping for one.
    #[test]
    fn a_body_split_across_segments_is_read_whole() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let body = r#"{"value":"split across two writes"}"#;

        let sender = std::thread::spawn(move || {
            let mut stream =
                TcpStream::connect(("127.0.0.1", port)).expect("connect to the reader");
            write!(
                stream,
                "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .expect("write headers");
            stream.flush().expect("flush headers");
            // Long enough that the reader's first read returns headers only.
            std::thread::sleep(std::time::Duration::from_millis(120));
            stream.write_all(body.as_bytes()).expect("write body");
            stream.flush().expect("flush body");
        });

        let (mut accepted, _) = listener.accept().expect("accept");
        let request = read_http_request(&mut accepted).expect("read the request");
        sender.join().expect("sender finishes");

        assert!(
            request.ends_with(body),
            "the delayed body must be present in full: {request:?}"
        );
    }

    /// Send `raw` to a fresh listener and read it back with the stub reader.
    fn read_back(raw: Vec<u8>) -> Result<String, String> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let sender = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            // A peer that stops reading makes this write fail; that is fine.
            let _ = stream.write_all(&raw);
            let _ = stream.flush();
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        let (mut accepted, _) = listener.accept().expect("accept");
        accepted
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("read timeout");
        let request = read_http_request(&mut accepted);
        sender.join().expect("sender finishes");
        request
    }

    /// A chunked body is decoded, so the stub sees the JSON the client sent
    /// rather than the chunk framing around it.
    #[test]
    fn a_chunked_body_is_decoded() {
        let raw = b"POST /v1/issues HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                    9\r\n{\"title\":\r\n8;ext=1\r\n\"hello\"}\r\n0\r\n\r\n"
            .to_vec();
        let request = read_back(raw).expect("read the chunked request");
        let body = &request[request.find("\r\n\r\n").expect("terminator") + 4..];
        assert_eq!(
            body, r#"{"title":"hello"}"#,
            "the chunk framing reached the stub instead of the body"
        );
    }

    /// A request larger than the cap is refused instead of buffered whole,
    /// whether it declares its size up front or never ends its headers.
    #[test]
    fn an_oversize_request_is_refused() {
        let size = MAX_REQUEST_BYTES + 4096;
        let mut declared =
            format!("POST / HTTP/1.1\r\nContent-Length: {size}\r\n\r\n").into_bytes();
        declared.extend_from_slice(&vec![b'x'; size]);
        let error = read_back(declared).expect_err("a declared oversize body must be refused");
        assert!(error.contains("exceeds"), "{error}");

        let mut unterminated = b"POST / HTTP/1.1\r\nX-Flood: ".to_vec();
        unterminated.extend_from_slice(&vec![b'x'; size]);
        let error =
            read_back(unterminated).expect_err("headers that never end must not be buffered whole");
        assert!(error.contains("exceeds"), "{error}");
    }

    /// A transient accept error does not stop a stub: the next connection is
    /// still served.
    #[test]
    fn an_accept_error_does_not_end_the_accept_loop() {
        let running = AtomicBool::new(true);
        let mut attempts = vec![
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted)),
            Ok(7),
        ]
        .into_iter();
        let mut handled = Vec::new();
        accept_until_stopped(
            &running,
            || attempts.next().unwrap_or(Ok(0)),
            |stream| {
                handled.push(stream);
                running.store(false, Ordering::Release);
            },
        );
        assert_eq!(handled, vec![7], "the loop ended at the accept error");
    }

    /// The response formatter declares a length matching the body it carries.
    ///
    /// A mismatch here is the worst kind of stub bug: a client reading
    /// `Content-Length` bytes either truncates the body or blocks waiting for
    /// bytes that never come, and the failure surfaces in whatever test used the
    /// stub rather than in the stub itself.
    ///
    /// Multi-byte content is used deliberately -- a formatter using character
    /// count instead of byte length passes an ASCII-only check.
    #[test]
    fn the_declared_length_matches_the_body_in_bytes() {
        let body = r#"{"tag":"café"}"#;
        let response = http_json(200, body);
        let declared: usize = response
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse().ok())
            })
            .expect("the response declares a content length");
        assert_eq!(
            declared,
            body.len(),
            "the declared length must be the BYTE length, not the character count"
        );
        assert!(
            response.ends_with(body),
            "the body must follow the header terminator: {response}"
        );
        assert!(
            http_empty(204).ends_with("\r\n\r\n"),
            "an empty response must still terminate its headers"
        );
    }
}
