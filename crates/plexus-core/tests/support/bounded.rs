#![allow(dead_code)]

//! Completion waits for test workers and child processes must not turn a missing event into a hung suite.

use std::future::Future;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const WAIT: Duration = Duration::from_secs(2);

// Store-backed race workers include serialized durable writes, not just a
// channel handoff. Ordinary full-run withdrawal rounds reached 1.175 s; shared
// disk stalls have also exceeded 2 s. Keep an order-of-magnitude margin over
// that measured round while retaining a finite deadlock watchdog.
pub const STORE_WORK_WAIT: Duration = Duration::from_secs(10);

/// Kill a long-running test service and reap it without blocking indefinitely.
/// A timed-out destructor must not defeat the test's outer async deadline.
pub fn kill_and_wait_within(
    child: &mut std::process::Child,
    timeout: Duration,
    label: &str,
) -> std::io::Result<std::process::ExitStatus> {
    let _ = child.kill();
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{label}: child did not exit within {timeout:?} after kill"),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Wait for a channel message without letting a missing reply hang its test.
pub async fn recv_within<T>(
    receive: impl Future<Output = Option<T>>,
    timeout: Duration,
    expected: &str,
) -> T {
    match recv_option_within(receive, timeout, expected).await {
        Some(value) => value,
        None => panic!("{expected}: reply channel closed before a reply arrived"),
    }
}

/// Bound a receive where channel closure is itself an expected outcome.
pub async fn recv_option_within<T>(
    receive: impl Future<Output = Option<T>>,
    timeout: Duration,
    expected: &str,
) -> Option<T> {
    match tokio::time::timeout(timeout, receive).await {
        Ok(value) => value,
        Err(_) => panic!("{expected}: timed out waiting {timeout:?} for a reply"),
    }
}

pub struct Task<T> {
    done: mpsc::Receiver<std::thread::Result<T>>,
    thread: JoinHandle<()>,
}

impl<T: Send + 'static> Task<T> {
    pub fn spawn(work: impl FnOnce() -> T + Send + 'static) -> Self {
        let (tx, done) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
            let _ = tx.send(result);
        });
        Self { done, thread }
    }

    pub fn join(self) -> Result<T, String> {
        self.join_timeout(WAIT)
    }

    pub fn join_timeout(self, timeout: Duration) -> Result<T, String> {
        let result = self.done.recv_timeout(timeout).map_err(|error| {
            // Dropping a JoinHandle detaches it: never autojoin an unresponsive
            // worker while unwinding the test that should report the failure.
            format!("test worker did not finish within {timeout:?}: {error}")
        })?;
        // The result is sent immediately before return, with no further I/O.
        self.thread
            .join()
            .map_err(|_| "test worker panicked after completion".to_owned())?;
        result.map_err(|panic| {
            panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "test worker panicked".to_owned())
        })
    }
}

/// Spawn a child with concurrent pipe drains and a hard completion deadline.
/// The result preserves spawn errors so callers can retry transient executable-busy errors.
pub fn child_output(
    command: &mut std::process::Command,
    timeout: Duration,
    label: &str,
) -> std::io::Result<std::process::Output> {
    use std::io::Read;
    use std::process::Stdio;

    let name = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let deadline = Instant::now() + timeout;
    let mut child = loop {
        match command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => break child,
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                panic!("{label}: child command `{name}` remained busy for {timeout:?}: {error}");
            }
            Err(error) => return Err(error),
        }
    };
    let mut stdout = child.stdout.take().expect("piped child stdout");
    let mut stderr = child.stderr.take().expect("piped child stderr");
    let (out_tx, out_rx) = mpsc::channel();
    let (err_tx, err_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.read_to_end(&mut bytes).map(|_| bytes);
        let _ = out_tx.send(result);
    });
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stderr.read_to_end(&mut bytes).map(|_| bytes);
        let _ = err_tx.send(result);
    });

    let mut status = None;
    let mut out = None;
    let mut err = None;
    while status.is_none() || out.is_none() || err.is_none() {
        if status.is_none() {
            status = child.try_wait()?;
        }
        if out.is_none() {
            if let Ok(result) = out_rx.try_recv() {
                out = Some(result?);
            }
        }
        if err.is_none() {
            if let Ok(result) = err_rx.try_recv() {
                err = Some(result?);
            }
        }
        if status.is_some() && out.is_some() && err.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            terminate_child_tree(&mut child);
            panic!("{label}: child command `{name}` did not finish within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    Ok(std::process::Output {
        status: status.expect("child exited before completion"),
        stdout: out.expect("child stdout closed before completion"),
        stderr: err.expect("child stderr closed before completion"),
    })
}

fn terminate_child_tree(child: &mut std::process::Child) {
    use std::process::Stdio;
    #[cfg(unix)]
    {
        // The child owns a process group so descendants cannot keep its pipes
        // open after the leader exits. `kill` targets that group, not the test.
        let _ = std::process::Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}
