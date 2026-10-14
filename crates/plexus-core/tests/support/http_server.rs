//! A fixed-request fixture must finish even when local authorization sends fewer requests.

use crate::bounded;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct FixedRequestServer {
    task: Option<bounded::Task<Result<(), String>>>,
    stop: Arc<AtomicBool>,
    received: Arc<AtomicUsize>,
    expected: usize,
    label: &'static str,
    wait: Duration,
}

impl FixedRequestServer {
    pub fn start<F>(expected: usize, label: &'static str, handler: F) -> (String, Self)
    where
        F: Fn(usize, &str) -> String + Send + 'static,
    {
        Self::start_with_deadline(expected, label, bounded::WAIT, handler)
    }

    /// Keep fixture admission alive through the caller's bounded progress check.
    /// Use a longer deadline when dispatch first has to finish durable writes.
    pub fn start_with_deadline<F>(
        expected: usize,
        label: &'static str,
        wait: Duration,
        handler: F,
    ) -> (String, Self)
    where
        F: Fn(usize, &str) -> String + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::new(AtomicUsize::new(0));
        let task = {
            let stop = stop.clone();
            let received = received.clone();
            bounded::Task::spawn(move || {
                for index in 0..expected {
                    let deadline = Instant::now() + wait;
                    let mut socket = loop {
                        if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
                            return Err(format!(
                                "{label}: expected {expected} requests, got {}",
                                received.load(Ordering::SeqCst)
                            ));
                        }
                        match listener.accept() {
                            Ok((socket, _)) => break socket,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5))
                            }
                            Err(error) => return Err(format!("{label}: accept: {error}")),
                        }
                    };
                    // macOS inherits the listener's nonblocking flag on accept;
                    // socket timeouts only bound reads on a blocking socket.
                    socket.set_nonblocking(false).unwrap();
                    // Accepted sockets can precede the client's first write on
                    // a loaded host. Allow I/O more time than a missing request.
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    socket.set_write_timeout(Some(bounded::WAIT)).unwrap();
                    let mut reader = BufReader::new(&mut socket);
                    let mut request = String::new();
                    let mut content_length = 0;
                    loop {
                        let mut line = String::new();
                        if reader
                            .read_line(&mut line)
                            .map_err(|e| format!("{label}: read headers: {e}"))?
                            == 0
                        {
                            return Err(format!("{label}: incomplete request"));
                        }
                        request.push_str(&line);
                        if line == "\r\n" {
                            break;
                        }
                        if let Some(length) =
                            line.to_ascii_lowercase().strip_prefix("content-length:")
                        {
                            content_length = length
                                .trim()
                                .parse::<usize>()
                                .map_err(|e| format!("{label}: content length: {e}"))?;
                        }
                    }
                    let mut body = vec![0; content_length];
                    reader
                        .read_exact(&mut body)
                        .map_err(|e| format!("{label}: read body: {e}"))?;
                    request.push_str(&String::from_utf8_lossy(&body));
                    drop(reader);
                    received.fetch_add(1, Ordering::SeqCst);
                    let response = handler(index, &request);
                    let _ = socket.write_all(response.as_bytes());
                }
                Ok(())
            })
        };
        (
            format!("http://{address}"),
            Self {
                task: Some(task),
                stop,
                received,
                expected,
                label,
                wait,
            },
        )
    }

    // Preserve the helpers' join interface so every existing caller gets the
    // same deadline and request-count diagnostic, rather than bespoke cleanup.
    pub fn join(mut self) -> Result<(), String> {
        let result = self
            .task
            .take()
            .unwrap()
            .join_timeout(self.wait.max(Duration::from_secs(6)));
        self.stop.store(true, Ordering::SeqCst);
        result.map_err(|error| {
            format!(
                "{}: expected {} requests, got {}; {error}",
                self.label,
                self.expected,
                self.received.load(Ordering::SeqCst)
            )
        })?
    }
}

impl Drop for FixedRequestServer {
    fn drop(&mut self) {
        // A panic before join must also release the accept loop. Do not wait on
        // a handler here: unwinding is never allowed to autojoin a stuck worker.
        self.stop.store(true, Ordering::SeqCst);
    }
}
