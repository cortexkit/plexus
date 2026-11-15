//! Keeps plexus's routing declaration in step with its live web search
//! connections.
//!
//! Routing only chooses among search routes a module declares in its daemon
//! catalog entry. HELLO declares every route in the provider table, because
//! the store cannot be read before HELLO. After readiness, and on every
//! scheduler pass after that, plexus works out which routed providers have a
//! live connection and, when that set differs from what it last declared,
//! replaces its declaration with `catalog.update_role_declarations` on its
//! own daemon connection. Routing rereads the catalog about every 30 seconds,
//! so a route just added is not chosen at once; the search service is told
//! when routes are added so it can read an early `no_route` as "not seen yet".

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use plexus_core::web_search::routing::{self, RouteRef};
use plexus_core::web_search::WebSearchService;
use plexus_core::PlexusStore;
use subc_protocol::session::{ModuleControlRequestFromModule, ModuleControlResponseToModule};
use subc_protocol::{ErrorBody, Frame, FrameType};
use tokio::sync::mpsc;

use crate::scope_reader::PendingControlReplies;

/// How long one declaration update may take before it counts as unanswered.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct SearchDeclarations {
    writer: mpsc::Sender<Frame>,
    version: u8,
    pending: Arc<PendingControlReplies>,
    /// The routes the daemon catalog currently carries for plexus.
    declared: Mutex<Vec<RouteRef>>,
    /// Connected providers without a catalog row already logged, so each is
    /// named once per process rather than on every pass.
    unrouted_logged: Mutex<BTreeSet<&'static str>>,
}

impl SearchDeclarations {
    pub fn new(
        writer: mpsc::Sender<Frame>,
        version: u8,
        pending: Arc<PendingControlReplies>,
    ) -> Self {
        Self {
            writer,
            version,
            pending,
            // What the HELLO manifest declared.
            declared: Mutex::new({
                let mut routes = routing::table_routes();
                routes.sort();
                routes
            }),
            unrouted_logged: Mutex::new(BTreeSet::new()),
        }
    }

    /// Bring the declaration in line with the live connections of
    /// `principals`. Sends nothing when it already matches. A failed update
    /// is logged and retried on the next call.
    pub fn reconcile(&self, store: &PlexusStore, principals: &[String], search: &WebSearchService) {
        let (live, unrouted) = match routing::live_routes(store, principals) {
            Ok(found) => found,
            Err(error) => {
                plexus_core::diag!(warn web_search: "web search routes could not be read for the routing declaration: {error}");
                return;
            }
        };
        {
            let mut logged = self
                .unrouted_logged
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for provider in unrouted {
                if logged.insert(provider) {
                    plexus_core::diag!(info web_search:
                        "web search provider {provider} is connected but has no routing catalog row, so it is not declared and searches will not use it"
                    );
                }
            }
        }
        let mut declared = self
            .declared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *declared == live {
            return;
        }
        if let Err(error) = crate::blocking_section(|| self.send(&live)) {
            plexus_core::diag!(warn web_search: "routing declaration update failed: {error}");
            return;
        }
        if live.iter().any(|route| !declared.contains(route)) {
            search.note_routes_added();
        }
        plexus_core::diag!(info web_search:
            "routing declaration now lists {} web search route(s)", live.len()
        );
        *declared = live;
    }

    fn send(&self, routes: &[RouteRef]) -> Result<(), String> {
        let declarations = serde_json::to_value(routing::role_declarations(routes))
            .map_err(|error| format!("encode declarations: {error}"))?;
        let body = serde_json::to_vec(
            &ModuleControlRequestFromModule::CatalogUpdateRoleDeclarations {
                role_declarations: declarations,
            },
        )
        .map_err(|error| format!("encode catalog.update_role_declarations: {error}"))?;
        // One deadline covers queuing the request and waiting for the reply.
        let deadline = std::time::Instant::now() + UPDATE_TIMEOUT;
        let (correlation, replies) = self.pending.register().map_err(|error| error.0)?;
        let mut frame = Frame::build_with_version(
            self.version,
            FrameType::Request,
            crate::wire::control_flags(),
            0,
            0,
            correlation,
            body,
        )
        .map_err(|error| {
            self.pending.forget(correlation);
            format!("build catalog.update_role_declarations frame: {error}")
        })?;
        loop {
            match self.writer.try_send(frame) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.pending.forget(correlation);
                    return Err("the daemon connection is closed".into());
                }
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    if std::time::Instant::now() >= deadline {
                        self.pending.forget(correlation);
                        return Err("the daemon connection's send queue stayed full".into());
                    }
                    frame = returned;
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let reply = replies.recv_timeout(remaining).map_err(|_| {
            self.pending.forget(correlation);
            "the daemon did not answer catalog.update_role_declarations in time".to_string()
        })?;
        update_reply(&reply)
    }
}

/// Decode subc's reply to a `catalog.update_role_declarations`.
fn update_reply(reply: &Frame) -> Result<(), String> {
    if reply.header.ty == FrameType::Error {
        let detail = serde_json::from_slice::<ErrorBody>(&reply.body)
            .map(|body| format!("{}: {}", body.code, body.message))
            .unwrap_or_else(|_| "an unreadable error body".to_string());
        return Err(format!(
            "catalog.update_role_declarations refused: {detail}"
        ));
    }
    match serde_json::from_slice::<ModuleControlResponseToModule>(&reply.body) {
        Ok(ModuleControlResponseToModule::CatalogUpdateRoleDeclarations {}) => Ok(()),
        _ => Err("unexpected catalog.update_role_declarations reply".into()),
    }
}

#[cfg(test)]
#[path = "search_declarations_tests.rs"]
mod tests;
