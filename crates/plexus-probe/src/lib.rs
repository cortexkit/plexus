//! Sandboxed execution for author-supplied JavaScript probes.
//! The crate owns only execution; probe registration, persistence, scheduling,
//! governance, and action dispatch are deliberately outside this boundary.

// Production code may contain no `unsafe` at all. Test builds relax `forbid`
// to `deny` for one reason: a test installs a counting global allocator
// (an `unsafe impl`) to prove that guest-supplied lengths cannot choose the
// size of a host allocation, and `forbid` cannot be lifted for a single item.
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

mod sandbox;
mod schema;

pub use sandbox::{
    ActionInvoker, ProbeError, ProbeSandbox, MAX_SOURCE_BYTES, MEMORY_LIMIT_BYTES, RUN_CEILING,
    WALL_TIMEOUT,
};
pub use schema::{
    ProbeValue, ReturnSchema, ReturnSchemaError, ReturnValidationError, ScalarSchema, ScalarValue,
};
