//! Fixtures shared by this crate's unit tests.

/// An `http://127.0.0.1:<port><path>` URL on which nothing listens.
///
/// For tests that need a transport to try a vendor and fail at once. A closed
/// loopback port refuses the connection locally, whereas an unresolvable name
/// such as `vendor.invalid` still sends a DNS query (or, behind a proxy, a
/// CONNECT) off the machine. The port comes from binding port 0 and closing
/// the listener, so it was free a moment ago and no fixed port is assumed.
pub(crate) fn closed_loopback_url(path: &str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let address = listener.local_addr().expect("loopback port address");
    drop(listener);
    format!("http://{address}{path}")
}

/// Fail unless an HTTP request to `127.0.0.1` would go straight to loopback.
///
/// The vendor transports honour the standard proxy variables. With
/// `HTTP_PROXY` or `ALL_PROXY` set and loopback not exempted by `NO_PROXY`, a
/// request meant for a test's loopback stub is sent to the proxy instead: the
/// test leaves the machine, and a stub that counts contacts sees none, so a
/// "no vendor contact" assertion passes even when a request was sent. Tests
/// that dial a loopback stub call this first so that environment fails loudly
/// rather than quietly testing nothing.
pub(crate) fn assert_loopback_is_not_proxied() {
    if let Some(variable) = loopback_proxy_variable(|name| std::env::var(name).ok()) {
        panic!(
            "{variable} is set and NO_PROXY does not exempt 127.0.0.1, so this test's \
             loopback stub would be reached through a proxy; unset {variable} or add \
             127.0.0.1 to NO_PROXY for the test run"
        );
    }
}

/// The proxy variable that would carry a plain-HTTP request for `127.0.0.1`,
/// if any. Mirrors how the HTTP client reads its environment: the first set
/// spelling of each variable wins (upper case before lower case, even when
/// empty), `HTTP_PROXY` before `ALL_PROXY`, and `NO_PROXY` exempts an address
/// only by an exact IP or a CIDR block containing it. A `*` entry exempts
/// host names, not addresses, so it does not protect the stubs.
fn loopback_proxy_variable(lookup: impl Fn(&str) -> Option<String>) -> Option<&'static str> {
    let first_set = |names: [&'static str; 2]| {
        names
            .into_iter()
            .find_map(|name| lookup(name).map(|value| (name, value)))
    };
    let variable = [["HTTP_PROXY", "http_proxy"], ["ALL_PROXY", "all_proxy"]]
        .into_iter()
        .filter_map(first_set)
        .find(|(_, value)| !value.trim().is_empty())
        .map(|(name, _)| name)?;
    let exemptions = first_set(["NO_PROXY", "no_proxy"])
        .map(|(_, value)| value)
        .unwrap_or_default();
    let exempt = exemptions
        .split(',')
        .map(str::trim)
        .any(|entry| entry == "127.0.0.1" || cidr_holds_loopback(entry));
    (!exempt).then_some(variable)
}

fn cidr_holds_loopback(entry: &str) -> bool {
    let Some((network, prefix)) = entry.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(prefix)) = (network.parse::<std::net::Ipv4Addr>(), prefix.parse::<u32>())
    else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    u32::from(network) & mask == u32::from(std::net::Ipv4Addr::LOCALHOST) & mask
}

#[test]
fn loopback_proxy_detection_follows_the_client_rules() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    };
    assert_eq!(loopback_proxy_variable(env(&[])), None);
    // An HTTPS-only proxy never carries the plain-HTTP loopback stubs.
    assert_eq!(
        loopback_proxy_variable(env(&[("HTTPS_PROXY", "http://proxy:3128")])),
        None
    );
    assert_eq!(
        loopback_proxy_variable(env(&[("HTTP_PROXY", "http://proxy:3128")])),
        Some("HTTP_PROXY")
    );
    assert_eq!(
        loopback_proxy_variable(env(&[("all_proxy", "socks5://proxy:1080")])),
        Some("all_proxy")
    );
    for exemption in ["127.0.0.1", "10.0.0.0/8, 127.0.0.0/8", "127.0.0.1/32"] {
        assert_eq!(
            loopback_proxy_variable(|name: &str| match name {
                "HTTP_PROXY" => Some("http://proxy:3128".to_string()),
                "no_proxy" => Some(exemption.to_string()),
                _ => None,
            }),
            None,
            "{exemption}"
        );
    }
    // `*` and `localhost` exempt host names, and the stubs dial an address.
    for not_an_exemption in ["128.0.0.0/8", "*", "localhost"] {
        assert_eq!(
            loopback_proxy_variable(|name: &str| match name {
                "ALL_PROXY" => Some("http://proxy:3128".to_string()),
                "NO_PROXY" => Some(not_an_exemption.to_string()),
                _ => None,
            }),
            Some("ALL_PROXY"),
            "{not_an_exemption}"
        );
    }
    // The upper-case spelling shadows the lower-case one even when empty.
    assert_eq!(
        loopback_proxy_variable(env(&[
            ("HTTP_PROXY", "http://proxy:3128"),
            ("NO_PROXY", ""),
            ("no_proxy", "127.0.0.1")
        ])),
        Some("HTTP_PROXY")
    );
    assert_eq!(
        loopback_proxy_variable(env(&[
            ("HTTP_PROXY", ""),
            ("http_proxy", "http://proxy:3128")
        ])),
        None
    );
}

/// Fail unless `output`, from re-running this test binary with
/// `--exact <test>`, shows that exactly one test ran and passed.
///
/// `--exact` with a name that matches nothing runs zero tests and exits 0. A
/// parent whose own checks are only absences (no secret in the log) would then
/// pass without its scenario ever running, for example after the test or its
/// module is renamed.
pub(crate) fn assert_exactly_one_test_passed(test: &str, output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed;")),
        "child run of {test} did not run exactly one test, or it did not pass: {stdout}"
    );
}

/// The scheduler tick unit tests run: short enough that waiting for a few
/// passes takes milliseconds, where the module's one-second tick would make
/// each wait a second.
pub(crate) const TEST_SCHEDULER_TICK: std::time::Duration = std::time::Duration::from_millis(20);

/// Generous on purpose: it only has to catch a scheduler that never runs, and
/// a tight bound would fail on a loaded machine instead.
const SCHEDULER_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// The real scheduler task, ticking every `TEST_SCHEDULER_TICK`.
pub(crate) fn spawn_test_scheduler(
    state: std::sync::Arc<crate::ModuleState>,
    stop: tokio::sync::mpsc::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    crate::spawn_trigger_scheduler_every(
        TEST_SCHEDULER_TICK,
        state,
        stop,
        crate::DEFAULT_AUDIT_RETENTION_DAYS * crate::AUDIT_MILLIS_PER_DAY,
    )
}

/// Wait until the scheduler has begun `passes` more passes, and say whether
/// it did within `SCHEDULER_WAIT`.
///
/// Passes never overlap (the next tick is taken only after a pass returns),
/// so once two passes have begun after this call, the first of them has also
/// finished: waiting for two means one whole pass ran after the call.
pub(crate) async fn scheduler_passes(health: &crate::health::HealthState, passes: usize) -> bool {
    let mut last = health.last_scheduler_pass_ms_for_test();
    let mut seen = 0;
    tokio::time::timeout(SCHEDULER_WAIT, async {
        while seen < passes {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            let stamp = health.last_scheduler_pass_ms_for_test();
            if stamp != last {
                seen += 1;
                last = stamp;
            }
        }
    })
    .await
    .is_ok()
}

/// Poll `ready` every few milliseconds until it holds or `limit` passes, and
/// say whether it held.
pub(crate) async fn eventually(
    limit: std::time::Duration,
    mut ready: impl FnMut() -> bool,
) -> bool {
    tokio::time::timeout(limit, async {
        while !ready() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok()
}
