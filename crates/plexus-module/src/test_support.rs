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
