use super::*;

/// The cases asserted here must render distinctly from one another.
///
/// Inequality rather than "the message contains X", because a containment
/// assertion passes against a formatter that returns one constant for every
/// variant -- which is what this formatter previously did with its payloads
/// discarded. The claim is limited to the pairs below; it is not a proof
/// that every possible cause renders distinctly.
#[test]
fn distinct_transport_failures_render_distinctly() {
    let refused = McpRemoteError::Connection.to_string();
    let unauthorized = McpRemoteError::AuthRejected.to_string();
    let forbidden = McpRemoteError::VendorStatus(403).to_string();
    let throttled = McpRemoteError::Throttled(Duration::from_secs(90)).to_string();

    // A connect-classified failure and an auth rejection: these two rendered
    // identically before the payloads were carried.
    assert_ne!(
        refused, unauthorized,
        "a connection failure and a rejected credential must be distinguishable"
    );

    // Different statuses must stay different. 401 and 403 are the pair a
    // reader is most likely to need apart, and collapsing both into
    // "authentication was rejected" loses the only detail that separates
    // them.
    assert_ne!(
        unauthorized, forbidden,
        "distinct auth statuses must remain distinguishable"
    );
    assert!(unauthorized.contains("401"), "got: {unauthorized}");
    assert!(forbidden.contains("403"), "got: {forbidden}");

    assert!(
        throttled.contains("90"),
        "the observed retry delay must reach the message: {throttled}"
    );
    assert_ne!(
        throttled,
        McpRemoteError::Throttled(Duration::from_secs(3600)).to_string(),
        "throttle delays of different magnitudes must be distinguishable"
    );

    let no_delay = McpRemoteError::Throttled(Duration::ZERO).to_string();
    assert!(
        !no_delay.contains("0s"),
        "an absent Retry-After means unknown, not immediate: {no_delay}"
    );
}

/// The catalog layer carries the transport cause rather than replacing it.
///
/// Asserted separately because the two layers discard detail independently:
/// the transport formatter dropping its payload and `CatalogError::Transport`
/// dropping the whole inner error are distinct defects, and fixing one while
/// the other stands still yields a message that still cannot be triaged.
/// Covers a connection failure against an HTTP 401 only; other causes and
/// other `CatalogError` variants are outside what this asserts.
#[test]
fn the_catalog_error_carries_the_transport_cause() {
    let refused = crate::catalog::CatalogError::Transport(McpRemoteError::Connection);
    let unauthorized = crate::catalog::CatalogError::Transport(McpRemoteError::AuthRejected);

    assert_ne!(
        refused.to_string(),
        unauthorized.to_string(),
        "the catalog layer must not flatten distinct transport causes"
    );
    assert!(
        unauthorized.to_string().contains("401"),
        "the status must survive the catalog layer: {unauthorized}"
    );
}
