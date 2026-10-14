#[path = "support/bounded.rs"]
mod bounded;

use std::process::Command;
use std::time::{Duration, Instant};

#[test]
#[cfg(unix)]
fn killed_test_service_is_reaped_within_its_deadline() {
    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("start test service");
    let status = bounded::kill_and_wait_within(
        &mut child,
        Duration::from_secs(2),
        "test service cleanup deadline",
    )
    .expect("killed test service must be reaped");
    assert!(
        !status.success(),
        "service must be killed, not left running"
    );
    assert_eq!(child.try_wait().unwrap(), Some(status));
}

async fn assert_missing_reply_is_bounded(expected: &'static str) {
    let (_sender, mut receiver) = tokio::sync::mpsc::channel::<()>(1);
    let task = tokio::spawn(async move {
        bounded::recv_within(receiver.recv(), Duration::from_millis(50), expected).await;
    });
    let failure = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("bounded receive helper exceeded its watchdog")
        .expect_err("a receive with no reply must panic at its deadline");
    assert!(failure.is_panic(), "the missing reply must panic by name");
}

#[tokio::test]
async fn missing_management_reply_fails_within_its_deadline() {
    assert_missing_reply_is_bounded("management response").await;
}

#[tokio::test]
async fn missing_route_reply_fails_within_its_deadline() {
    assert_missing_reply_is_bounded("tool route response").await;
}

#[tokio::test]
async fn missing_event_reply_fails_within_its_deadline() {
    assert_missing_reply_is_bounded("event acknowledgement").await;
}

#[test]
#[cfg(unix)]
#[should_panic(expected = "did not finish within 50ms")]
fn sleeping_diagnostic_child_is_killed_at_its_deadline() {
    let mut command = Command::new("sh");
    command.args(["-c", "sleep 1"]);
    let _ = bounded::child_output(&mut command, Duration::from_millis(50), "diagnostic child");
}

#[test]
#[cfg(unix)]
#[should_panic(expected = "did not finish within 50ms")]
fn sleeping_cli_child_is_killed_at_its_deadline() {
    let mut command = Command::new("sh");
    command.args(["-c", "sleep 1"]);
    let _ = bounded::child_output(&mut command, Duration::from_millis(50), "CLI child");
}

#[test]
#[cfg(unix)]
fn child_with_pipe_holding_descendant_is_killed_at_its_deadline() {
    let scratch = plexus_core::test_scratch::Scratch::directory("child-process-group");
    let descendant_file = scratch.path().join("descendant.pid");
    let group_file = scratch.path().join("group.pid");
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            r#"(trap '' HUP; sleep 30) & echo $! > "$DESCENDANT_PID_FILE"; echo $$ > "$GROUP_PID_FILE"; exit 0"#,
        ])
        .env("GROUP_PID_FILE", &group_file)
        .env("DESCENDANT_PID_FILE", &descendant_file);
    // The watchdog is independent of the child's deadline so a blocked pipe
    // drain fails this test instead of waiting for the descendant's 30s sleep.
    let worker = bounded::Task::spawn(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = bounded::child_output(
                &mut command,
                Duration::from_secs(1),
                "diagnostic child with a pipe-holding descendant",
            );
        }))
    });
    let result = worker.join_timeout(Duration::from_secs(5));
    let descendant = std::fs::read_to_string(&descendant_file).expect("descendant pid file");
    let group = std::fs::read_to_string(&group_file).expect("child group pid file");
    let cleanup = || {
        let mut cleanup = Command::new("kill");
        cleanup.args(["-KILL", "--", &format!("-{}", group.trim())]);
        let _ = bounded::child_output(
            &mut cleanup,
            Duration::from_secs(2),
            "clean up leaked child process group",
        );
    };
    if result.is_err() {
        cleanup();
    }
    let result = result.expect("child helper exceeded its deadline watchdog");
    let panic = result.expect_err("the child must time out while its descendant holds the pipes");
    let message = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            panic
                .downcast_ref::<&str>()
                .map(|message| (*message).to_owned())
        })
        .unwrap_or_else(|| "child helper did not report its timeout".to_owned());
    assert!(message.contains("did not finish within 1s"), "{message}");

    let mut probe = Command::new("ps");
    probe.args(["-o", "pid,ppid,pgid,stat,cmd", "-p", descendant.trim()]);
    // SIGKILL delivery is asynchronous. The helper reaps the group leader,
    // not its orphaned descendant, which ps can still see as runnable while
    // it exits. Observe termination within a separate bounded grace period;
    // do not send another signal until after recording a genuine leak.
    let exit_deadline = Instant::now() + Duration::from_secs(2);
    let (descendant_still_running, state) = loop {
        let output = bounded::child_output(
            &mut probe,
            Duration::from_secs(2),
            "check descendant process state",
        )
        .expect("run process-state check");
        let state = String::from_utf8_lossy(&output.stdout).into_owned();
        let descendant_state = state
            .lines()
            .nth(1)
            .and_then(|line| line.split_whitespace().nth(3))
            .unwrap_or("");
        let still_running = output.status.success() && !descendant_state.starts_with('Z');
        if !still_running || Instant::now() >= exit_deadline {
            break (still_running, state);
        }
    };

    if descendant_still_running {
        cleanup();
    }
    assert!(
        !descendant_still_running,
        "child helper left descendant {} running in group {}: {state}",
        descendant.trim(),
        group.trim()
    );
}

#[test]
fn a_worker_missing_completion_does_not_join_after_the_deadline() {
    let worker = bounded::Task::spawn(|| std::thread::sleep(Duration::from_secs(1)));
    let started = Instant::now();
    let error = worker
        .join_timeout(Duration::from_millis(50))
        .expect_err("the worker is still running");
    assert!(error.contains("test worker did not finish within 50ms"));
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[test]
fn a_second_missing_worker_completion_is_bounded() {
    let worker = bounded::Task::spawn(|| std::thread::sleep(Duration::from_secs(1)));
    let error = worker
        .join_timeout(Duration::from_millis(50))
        .expect_err("the worker is still running");
    assert!(error.contains("test worker did not finish within 50ms"));
}

#[test]
fn a_third_missing_worker_completion_is_bounded() {
    let worker = bounded::Task::spawn(|| std::thread::sleep(Duration::from_secs(1)));
    let error = worker
        .join_timeout(Duration::from_millis(50))
        .expect_err("the worker is still running");
    assert!(error.contains("test worker did not finish within 50ms"));
}
