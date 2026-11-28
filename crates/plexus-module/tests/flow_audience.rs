#[path = "support/flow_audience_core.rs"]
mod core_fixture;
#[path = "support/event_fixtures.rs"]
mod event_fixtures;

// The flow_audience:: filter selects the cases, not the subprocess entry point.
#[path = "support/flow_audience_cases.rs"]
mod flow_audience;
