//! Frame helpers for the ck-plexus wire edge.

use serde_json::{json, Value};
use subc_protocol::{ErrorBody, Flags, Frame, FrameType, Priority};

/// Build a `store_failure` wire error while recording the real cause to the
/// daemon log.
///
/// Every store error on the facade was reported as a fixed sentence with the
/// underlying error dropped by an `Err(_)` arm, and this module writes nothing
/// server-side -- so the cause existed for the width of a match arm and then
/// ceased to exist anywhere. Diagnosing one meant reading migration source to
/// work out which constraint had fired.
///
/// `StoreError`'s own Display is specific enough to end that guessing
/// ("storage backend: CHECK constraint failed: cursor_kind IN (...)"), so the
/// only thing missing was somewhere to put it.
///
/// THE DETAIL GOES TO THE LOG, NOT THE WIRE. The facade is agent-facing, and an
/// agent cannot act on a constraint violation -- the remedy is a migration,
/// which is an operator's job. Keeping the wire message fixed also keeps it
/// stable for callers that match on it, while the operator gets the sentence
/// that locates the fault.
///
/// FORMATTED ONCE AND WRITTEN ONCE, deliberately. Supervised modules inherit the
/// daemon's stderr, so every module shares one descriptor and one file offset,
/// and an emitter that writes per fragment interleaves with other processes
/// mid-line. A single pre-formatted write cannot be spliced.
pub(crate) fn store_failure(
    operation: &str,
    message: &str,
    error: &impl std::fmt::Display,
) -> Value {
    eprintln!(warn storage: "store failure during {operation}: {error}");
    json!({"error": {"code": "store_failure", "message": message}})
}

pub fn control_flags() -> Flags {
    Flags::new(false, Priority::Passive, false)
}

pub fn build_error_frame(
    version: u8,
    channel: u16,
    epoch: u32,
    correlation: u64,
    code: &str,
    message: &str,
) -> Result<Frame, crate::ModuleError> {
    let body =
        serde_json::to_vec(&ErrorBody::new(code, message)).map_err(crate::ModuleError::Json)?;
    Frame::build_with_version(
        version,
        FrameType::Error,
        control_flags(),
        channel,
        epoch,
        correlation,
        body,
    )
    .map_err(|error| crate::ModuleError::Message(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cause reaches the log and NOT the wire.
    ///
    /// Both halves matter and they pull in opposite directions. Dropping the
    /// cause entirely is the defect this helper exists to fix: the store error
    /// was discarded by an `Err(_)` arm in a module that writes nothing
    /// server-side, so it ceased to exist anywhere and diagnosing one meant
    /// reading migration source.
    ///
    /// Putting it on the WIRE is the over-correction, and it is the easier
    /// mistake to make while fixing the first. A backend error string is
    /// written for whoever operates the store, not for the agent that called
    /// the facade: it names internal schema, it cannot be acted on by the
    /// caller, and a wire message that varies with the underlying fault is one
    /// no caller can match on.
    ///
    /// Asserted as an absence rather than by inspecting the message, because a
    /// containment check on the fixed text would still pass if the cause were
    /// appended after it.
    ///
    /// Mutation-proved: folding the error into the wire message fails the
    /// absence assertion; returning the message without the eprintln leaves the
    /// first assertion passing, which is why the log is exercised by the
    /// integration path rather than claimed here.
    #[test]
    fn the_cause_stays_off_the_wire() {
        let cause = "CHECK constraint failed: cursor_kind IN ('sync_token')";
        let value = store_failure(
            "subscription create",
            "subscription could not be created",
            &cause,
        );

        assert_eq!(value["error"]["code"], "store_failure");
        assert_eq!(
            value["error"]["message"], "subscription could not be created",
            "the wire message must stay fixed so callers can match on it"
        );

        let rendered = value.to_string();
        assert!(
            !rendered.contains("CHECK constraint"),
            "the backend cause must not reach an agent-facing response: {rendered}"
        );
        assert!(
            !rendered.contains("cursor_kind"),
            "internal schema names must not reach an agent-facing response: {rendered}"
        );
    }

    #[test]
    fn error_frame_uses_control_flags() {
        let frame = build_error_frame(
            subc_protocol::PROTOCOL_VERSION,
            0,
            0,
            1,
            "principal_denied",
            "not eligible",
        )
        .expect("build error frame");
        assert_eq!(frame.header.ty, FrameType::Error);
        assert_eq!(
            frame.header.flags.priority(),
            Some(subc_protocol::Priority::Passive)
        );
    }
}
