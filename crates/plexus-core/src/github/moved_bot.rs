//! A paired-computer claim may select only the bot of an agent living there.

use subc_protocol::scope::{FederatedPeerClass, RemoteClaim};
use subc_protocol::Principal;

use crate::agent_registry::{AgentLookup, AgentRegistry, AgentResidence};
use crate::federated::FederatedCaller;

/// Stamped facts that can be checked without I/O. They are not yet authority.
#[derive(Clone, Copy)]
pub struct Claim<'a> {
    agent_id: &'a str,
    box_id: &'a str,
    module_id: &'a str,
    kind: ClaimKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimKind {
    Agent,
    Run,
    Flow,
}

impl<'a> Claim<'a> {
    pub fn from_caller(caller: &'a FederatedCaller) -> Option<Self> {
        let facts = &caller.attributes;
        if facts.peer_class != FederatedPeerClass::Computer {
            return None;
        }
        let (agent_id, kind) = match facts.remote_claim.as_ref()? {
            RemoteClaim::Agent { agent_id, .. } => (agent_id, ClaimKind::Agent),
            RemoteClaim::Run { agent_id, .. } => (agent_id, ClaimKind::Run),
            RemoteClaim::Flow {
                agent_id: Some(agent_id),
                ..
            } => (agent_id, ClaimKind::Flow),
            _ => return None,
        };
        let Principal::Reserved { module_id } = facts.origin_principal.as_ref()? else {
            return None;
        };
        if agent_id.is_empty() || module_id.is_empty() {
            return None;
        }
        Some(Self {
            agent_id,
            box_id: facts.peer_box_id.as_deref()?,
            module_id,
            kind,
        })
    }

    pub fn module_id(&self) -> &str {
        self.module_id
    }

    pub fn is_flow(&self) -> bool {
        self.kind == ClaimKind::Flow
    }

    pub fn admit(self, registry: &'a dyn AgentRegistry) -> Option<MovedBot<'a>> {
        let residence = registry.remote_residence(self.agent_id)?;
        if residence.holder_box != self.box_id
            || registry.lookup(self.agent_id) != AgentLookup::Known
        {
            return None;
        }
        Some(MovedBot {
            claim: self,
            residence,
            registry,
        })
    }
}

/// Fresh proof of identity and residence. Repository binding and the surface's
/// normal grants still apply; this proof does not confer local route authority.
pub struct MovedBot<'a> {
    claim: Claim<'a>,
    residence: AgentResidence,
    registry: &'a dyn AgentRegistry,
}

impl MovedBot<'_> {
    pub fn agent_id(&self) -> &str {
        self.claim.agent_id
    }

    pub fn principal(&self) -> String {
        format!("reserved:{}", self.claim.module_id())
    }

    pub(crate) fn is_flow(&self) -> bool {
        self.claim.is_flow()
    }

    pub fn is_run(&self) -> bool {
        self.claim.kind == ClaimKind::Run
    }

    pub(crate) fn residence(&self) -> serde_json::Value {
        serde_json::json!(self.residence)
    }

    pub(crate) fn current_residence(&self) -> Option<AgentResidence> {
        self.registry.remote_residence(self.agent_id())
    }
}
