//! Substrate conformance harness for ck-plexus connectors.
//!
//! Every connector must pass the same ordered checklist before it is trusted:
//! connect, discover its catalog, an allowed read, an ask-first write, S3
//! escalation, denied calls, a stale-authorization abort, revoke, audit
//! completeness and secret safety (see [`ConformanceStep`]). Proving these
//! once per connector, in one order, is what lets the governance guarantees
//! hold for every vendor rather than only for the ones tested by hand.
//!
//! One runner executes the ordered checklist against a per-connector
//! `ConnectorFixture`. Fixtures describe the manifest, credential mode,
//! transport target, and expected action set. The same runner later drives
//! real vendors by swapping the transport target.

#![forbid(unsafe_code)]

mod artifact;
pub mod drift;
pub mod evidence;
pub mod fixture;
mod http_wire;
pub mod rest_stub_server;
pub mod runner;
pub mod stub_server;
pub mod wire_trace;

pub use artifact::write_owner_only;
pub use drift::{catalog_manifests, check_manifest, DriftReport, DriftVerdict};
pub use evidence::{ConformanceStep, RunEvidence, StepEvidence};
pub use fixture::{ConnectorFixture, TransportTarget, WritePath};
pub use rest_stub_server::{ExpectedCredential, StubRestRoute, StubRestServer};
pub use runner::{run_fixture, run_fixture_with_options, RunOptions};
pub use stub_server::{StubMcpServer, StubTool};
pub use wire_trace::{record_route_connect, TracingRoutePeer, WireTraceSink};
