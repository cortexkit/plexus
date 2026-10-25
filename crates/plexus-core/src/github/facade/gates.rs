//! Pre-vendor admission. Run these checks in the same order they are recorded in the audit log.
use crate::github::facade::request_map::{self, MappedRequest};
use crate::github::receipt::{Claim, Effect, Receipt};
use crate::github::resolver::{self, Binding, ResolvedRepositories};
use crate::governance::compose_policy_effect;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Handle {
    pub app_handle_id: String,
    pub agent_id: String,
    pub connection_id: String,
    pub connection_principal: String,
    pub credential_reference: String,
    pub status: String,
    pub proven: bool,
}

#[derive(Debug, Clone)]
pub struct Authority {
    pub module_grant: bool,
    pub agent_grant: bool,
    pub pair_allowed: bool,
    pub module_effect: String,
    pub agent_effect: Option<String>,
    pub baseline: Value,
}

/// The implementation must return store errors rather than treating them as missing grants.
pub trait GateStore {
    fn grant_cause(
        &self,
        _handle: &Handle,
        _caller: &str,
        _agent: &str,
        _mapped: &MappedRequest,
        _layer: crate::grant_refusal::Layer,
    ) -> crate::grant_refusal::Cause {
        crate::grant_refusal::Cause::Missing
    }
    fn handle(&self, id: &str) -> Result<Option<Handle>, String>;
    /// The GitHub App bot handle bound to `agent`, if it has one. An agent has
    /// at most one (`agent_id` is unique on the handle table).
    fn handle_for_agent(&self, agent: &str) -> Result<Option<Handle>, String>;
    fn binding(&self, repository: &str) -> Result<Option<(Binding, String)>, String>;
    /// `caller` is the module principal that sent the bot request. Its module
    /// grant on the handle connection is the module dimension; the agent's own
    /// grants are the agent dimension whichever module carried the call.
    fn authority(
        &self,
        handle: &Handle,
        caller: &str,
        agent: &str,
        mapped: &MappedRequest,
        repository: &str,
    ) -> Result<Authority, String>;
    fn receipt(
        &self,
        agent: &str,
        nonce: &str,
    ) -> Result<Option<crate::github::receipt::Receipt>, String>;
    #[allow(clippy::too_many_arguments)]
    fn claim(
        &self,
        agent: &str,
        nonce: &str,
        mapped: &MappedRequest,
        handle: &Handle,
        claim_owner: &str,
        baseline: &Value,
        effects: &[Effect],
        ask_first: bool,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Claim, String>;
}

#[derive(Debug, Clone)]
pub struct GateReply {
    pub gate: &'static str,
    pub refusal_code: Option<String>,
    pub grant_refusal: Option<crate::grant_refusal::GrantRefusal>,
    pub invalid_request_field: Option<String>,
    pub claimed_agent_id: Option<String>,
    pub app_handle_id: Option<String>,
    pub action: String,
    pub request_id: String,
    pub claim: Option<Claim>,
    pub mapped: Option<MappedRequest>,
    pub handle: Option<Handle>,
    /// The module principal that sent the request. Governed reads and writes
    /// run as this principal and the facade audit row names it.
    pub caller_principal: String,
    /// The daemon scope the caller's route was bound under, if any. Recorded
    /// on the facade and governed audit rows. A delegating scope names the
    /// agent of a request, and a scoped request
    /// re-checks its scope before each write it sends.
    pub scope: Option<crate::scope::CallScope>,
}

impl GateReply {
    fn refuse(mut self, gate: &'static str, code: impl Into<String>) -> Self {
        self.gate = gate;
        let code = code.into();
        assert!(
            !matches!(code.as_str(), "module_grant_absent" | "agent_grant_absent"),
            "layer refusals require detail"
        );
        self.refusal_code = Some(code);
        self
    }

    fn refuse_grant(
        mut self,
        target: crate::grant_refusal::GrantTarget,
        cause: crate::grant_refusal::Cause,
    ) -> Self {
        let refusal = crate::grant_refusal::GrantRefusal::new(target, cause);
        self.gate = "G6";
        self.refusal_code = Some(refusal.code().into());
        self.grant_refusal = Some(refusal);
        self
    }

    /// Log the stamped agent so an operator can diagnose a failed bot binding.
    fn refuse_g2(self, code: impl Into<String>) -> Self {
        let code = code.into();
        eprintln!(warn governance:
            "bot_request handle refused ({code}) for caller {}: stamped agent {}",
            self.caller_principal,
            self.claimed_agent_id.as_deref().unwrap_or("")
        );
        self.refuse("G2", code)
    }

    fn replay(mut self, row: Receipt, mapped: MappedRequest) -> Self {
        self.gate = "G4";
        self.refusal_code = row.refusal_code.clone();
        self.claim = Some(Claim::Replay(row));
        self.mapped = Some(mapped);
        self
    }
}

fn terminal_state(state: &str) -> bool {
    matches!(state, "completed" | "refused" | "outcome_unknown")
}

// A terminal receipt belongs to the stamped agent and canonical request, not
// to the repository's current binding. Reconstruct mapping only to compare the
// original fingerprint; this synthetic binding is never used to dispatch.
fn terminal_binding_replay(
    store: &impl GateStore,
    agent: &str,
    nonce: &str,
    request: &Value,
    expect: Option<&super::expectation::Expectation>,
    repository: &str,
    handle: &Handle,
) -> Result<Option<(Receipt, MappedRequest)>, String> {
    if nonce.is_empty() {
        return Ok(None);
    }
    let Some(mut row) = store.receipt(agent, nonce)? else {
        return Ok(None);
    };
    if !terminal_state(&row.state) && !row.effects.iter().all(|effect| effect.outcome.is_some()) {
        return Ok(None);
    }
    let binding = Binding {
        app_handle_id: handle.app_handle_id.clone(),
        connection_id: handle.connection_id.clone(),
    };
    let resolved = ResolvedRepositories {
        repositories: vec![repository.into()],
        binding: binding.clone(),
    };
    let Ok(mut mapped) = request_map::map(request, &resolved, repository) else {
        return Ok(None);
    };
    if let Some(expect) = expect {
        expect.fingerprint(&mut mapped);
    }
    if let Some(outcome) = super::vendor_band::recover_completed(&row, &mapped.request_kind) {
        row.state = "completed".into();
        row.outcome = Some(outcome);
    }
    if !terminal_state(&row.state) {
        return Ok(None);
    }
    if resolver::resolve(request, &handle.connection_id, |_| {
        Ok(Some(binding.clone()))
    })
    .is_err()
    {
        return Ok(None);
    }
    if row.request_fingerprint != mapped.fingerprint
        && (expect.is_some() || row.request_fingerprint.starts_with("exact-json-expect-v1:"))
    {
        return Err("nonce_payload_mismatch".into());
    }
    Ok((row.request_fingerprint == mapped.fingerprint).then_some((row, mapped)))
}

/// Admission checks for a GitHub bot request made on an agent's behalf. They
/// end before any credential is read or GitHub is contacted.
///
/// The checks are labeled G1, G2 and so on, and the label of the check that
/// refused is reported in the reply's `gate` field and on the audit rows.
/// The first check (G1) requires the route's daemon scope to let the call act
/// as its agent ([`crate::scope::CallScope::acting_agent`]): the scope
/// delegates, names the agent, and its owner is authorized. That agent picks
/// the bot: the handle used is the GitHub App bot bound to it. Every other
/// call is refused at G1 with `delegating_scope_required`.
///
/// The grant check (G6) then checks the calling module's grant and the
/// agent's own grant as it does for any bot request.
#[allow(clippy::too_many_arguments)]
pub fn run_scoped(
    store: &impl GateStore,
    caller_principal: &str,
    scope: Option<&crate::scope::CallScope>,
    request: &Value,
    nonce: &str,
    request_id: &str,
    claim_owner: &str,
    now: i64,
    lease_seconds: i64,
) -> GateReply {
    run_scoped_with_expect(
        store,
        caller_principal,
        scope,
        request,
        nonce,
        None,
        request_id,
        claim_owner,
        now,
        lease_seconds,
    )
}

/// Admission with an optional caller-pinned authority expectation.
#[allow(clippy::too_many_arguments)]
pub fn run_scoped_with_expect(
    store: &impl GateStore,
    caller_principal: &str,
    scope: Option<&crate::scope::CallScope>,
    request: &Value,
    nonce: &str,
    expect: Option<&Value>,
    request_id: &str,
    claim_owner: &str,
    now: i64,
    lease_seconds: i64,
) -> GateReply {
    run_scoped_mode(
        store,
        caller_principal,
        scope,
        request,
        nonce,
        expect,
        request_id,
        claim_owner,
        now,
        lease_seconds,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_scoped(
    store: &impl GateStore,
    caller_principal: &str,
    scope: Option<&crate::scope::CallScope>,
    request: &Value,
    nonce: &str,
    expect: Option<&Value>,
    request_id: &str,
    claim_owner: &str,
    now: i64,
    lease_seconds: i64,
) -> GateReply {
    run_scoped_mode(
        store,
        caller_principal,
        scope,
        request,
        nonce,
        expect,
        request_id,
        claim_owner,
        now,
        lease_seconds,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_scoped_mode(
    store: &impl GateStore,
    caller_principal: &str,
    scope: Option<&crate::scope::CallScope>,
    request: &Value,
    nonce: &str,
    expect: Option<&Value>,
    request_id: &str,
    claim_owner: &str,
    now: i64,
    lease_seconds: i64,
    replay_only: bool,
) -> GateReply {
    // The routing repository is looked up, fingerprinted and sent in its
    // canonical (lowercase) form, so a request naming `Org/Repo` is the same
    // request, on the same binding, as one naming `org/repo`.
    let mut canonical = request.clone();
    if let Some(repository) = request.get("repository").and_then(Value::as_str) {
        canonical["repository"] = Value::String(crate::github::canonical_repository(repository));
    }
    let request = &canonical;
    let mut reply = GateReply {
        gate: "G1",
        refusal_code: None,
        grant_refusal: None,
        invalid_request_field: None,
        claimed_agent_id: None,
        app_handle_id: None,
        action: "github.bot_request".into(),
        request_id: request_id.into(),
        claim: None,
        mapped: None,
        handle: None,
        caller_principal: caller_principal.into(),
        scope: scope.cloned(),
    };
    let Some(agent) = scope.and_then(crate::scope::CallScope::acting_agent) else {
        return reply.refuse("G1", "delegating_scope_required");
    };
    reply.claimed_agent_id = Some(agent.to_string());
    let expect = match expect
        .map(super::expectation::Expectation::parse)
        .transpose()
    {
        Ok(expect) => expect,
        Err(field) => {
            reply.invalid_request_field = Some(field);
            return reply.refuse("G3", "invalid_request");
        }
    };
    let handle = match store.handle_for_agent(agent) {
        Ok(Some(row)) => row,
        Ok(None) => return reply.refuse_g2("agent_handle_unknown"),
        Err(code) => return reply.refuse_g2(code),
    };
    // A bot binding must name both this agent and this App's credential.
    if handle.agent_id != agent
        || handle.credential_reference
            != crate::github::credential::app_reference(&handle.app_handle_id)
    {
        return reply.refuse_g2("agent_handle_unknown");
    }
    reply.app_handle_id = Some(handle.app_handle_id.clone());
    let agent = agent.to_string();
    let repository = match request.get("repository").and_then(Value::as_str) {
        Some(repository) => repository,
        None => return reply.refuse_g2("repository_unbound"),
    };
    let (binding, bound_agent) = match store.binding(repository) {
        Ok(Some(binding)) => binding,
        Ok(None) => {
            match terminal_binding_replay(
                store,
                &agent,
                nonce,
                request,
                expect.as_ref(),
                repository,
                &handle,
            ) {
                Ok(Some((row, mapped))) => return reply.replay(row, mapped),
                Err(code) => return reply.refuse("G4", code),
                Ok(None) => {}
            }
            return reply.refuse_g2("repository_unbound");
        }
        Err(code) => return reply.refuse_g2(code),
    };
    if binding.app_handle_id != handle.app_handle_id {
        match terminal_binding_replay(
            store,
            &agent,
            nonce,
            request,
            expect.as_ref(),
            repository,
            &handle,
        ) {
            Ok(Some((row, mapped))) => return reply.replay(row, mapped),
            Err(code) => return reply.refuse("G4", code),
            Ok(None) => {}
        }
        return reply.refuse_g2(format!(
            "agent_repository_conflict{{claimed_agent: {}, bound_agent: {bound_agent}}}",
            agent
        ));
    }
    let resolved = ResolvedRepositories {
        repositories: vec![repository.into()],
        binding,
    };
    if nonce.is_empty() {
        return reply.refuse("G3", "request_field_forbidden{field: request_nonce}");
    }
    let mut mapped = match request_map::map(request, &resolved, repository) {
        Ok(mapped) => mapped,
        Err(code) => return reply.refuse("G3", code),
    };
    if let Some(expect) = &expect {
        expect.fingerprint(&mut mapped);
    }
    // Reject alternate repository fields before a receipt lookup can replay a request.
    if let Err(error) = resolver::resolve(request, &handle.connection_id, |name| {
        store
            .binding(name)
            .map(|row| row.map(|(binding, _)| binding))
            .map_err(|_| crate::governance::ResolverDenial::StoreFailure)
    }) {
        return reply.refuse(
            "G3",
            match error {
                crate::governance::ResolverDenial::RequestFieldForbidden { field } => {
                    format!("request_field_forbidden{{field: {field}}}")
                }
                crate::governance::ResolverDenial::StoreFailure => "store_failure".into(),
                crate::governance::ResolverDenial::RepositoryUnbound => "repository_unbound".into(),
            },
        );
    }
    match store.receipt(&agent, nonce) {
        Ok(Some(mut existing)) => {
            if existing.request_fingerprint != mapped.fingerprint {
                return reply.refuse("G4", "nonce_payload_mismatch");
            }
            if let Some(outcome) =
                super::vendor_band::recover_completed(&existing, &mapped.request_kind)
            {
                existing.state = "completed".into();
                existing.outcome = Some(outcome);
            }
            if terminal_state(&existing.state) {
                return reply.replay(existing, mapped);
            }
            let attempted = existing
                .effects
                .iter()
                .any(|effect| effect.dispatch_attempted_at.is_some());
            if existing.state == "pending"
                && existing
                    .claim_lease_expires_at
                    .is_some_and(|until| until > now)
            {
                if replay_only {
                    if !attempted {
                        return reply.refuse("G4", "store_failure");
                    }
                    reply.claim = Some(Claim::InFlight);
                }
                return reply.refuse("G4", "nonce_in_flight");
            }
            if replay_only && attempted {
                // Replay-only mode runs when the store's generation counter for
                // GitHub repository bindings could not be read, and without it
                // no new claim can be made. Normally an expired receipt whose
                // earlier attempt already sent some of its writes is claimed
                // again to send the rest. Here, report that the outcome is
                // unknown (some writes may have executed) and leave the stored
                // receipt unchanged, so a later retry with the same nonce, made
                // when the counter can be read, can still resume those writes.
                let mut uncertain = existing;
                uncertain.state = "outcome_unknown".into();
                uncertain.outcome = Some(serde_json::json!({"status":"outcome_unknown"}));
                reply.gate = "G4";
                reply.claim = Some(Claim::Unknown(uncertain));
                reply.mapped = Some(mapped);
                return reply;
            }
        }
        Ok(None) => {}
        Err(code) => return reply.refuse("G4", code),
    }
    if replay_only {
        return reply.refuse("G4", "store_failure");
    }
    if handle.status != "enabled" {
        return reply.refuse("G5", "handle_disabled");
    }
    if !handle.proven {
        return reply.refuse("G5", "probe_unproven");
    }
    // A caller with no live module grant on this handle connection (including
    // `direct` and any unknown module) refuses module_grant_absent below.
    let authority = match store.authority(&handle, caller_principal, &agent, &mapped, repository) {
        Ok(authority) => authority,
        Err(code) if code == "module_grant_absent" => {
            return reply.refuse_grant(
                crate::grant_refusal::GrantTarget::new(
                    crate::grant_refusal::Layer::Module,
                    caller_principal,
                    "github",
                    Some(&handle.connection_id),
                    mapped.action,
                ),
                crate::grant_refusal::Cause::Missing,
            );
        }
        Err(code) => return reply.refuse("G6", code),
    };
    // Compare with the authority baseline that the receipt will pin, not the
    // facade's earlier generation preflight. G2 must first establish that the
    // agent's handle is bound to this repository; terminal nonce replay above
    // must still return its recorded outcome even after authority has moved.
    // No claim, ownership pre-read or credential preparation has happened yet.
    if let Some(expect) = &expect {
        if expect.app_handle_id != handle.app_handle_id {
            return reply.refuse("G6", "stale_authority{dimension: expected_handle}");
        }
        if Some(expect.repo_binding_generation)
            != authority
                .baseline
                .get("repo_binding_generation")
                .and_then(Value::as_u64)
        {
            return reply.refuse("G6", "stale_authority{dimension: expected_binding}");
        }
    }
    if !authority.module_grant {
        return reply.refuse_grant(
            crate::grant_refusal::GrantTarget::new(
                crate::grant_refusal::Layer::Module,
                caller_principal,
                "github",
                Some(&handle.connection_id),
                mapped.action,
            ),
            store.grant_cause(
                &handle,
                caller_principal,
                &agent,
                &mapped,
                crate::grant_refusal::Layer::Module,
            ),
        );
    }
    if !authority.agent_grant {
        return reply.refuse_grant(
            crate::grant_refusal::GrantTarget::new(
                crate::grant_refusal::Layer::Agent,
                &agent,
                "github",
                Some(&handle.connection_id),
                mapped.action,
            ),
            store.grant_cause(
                &handle,
                caller_principal,
                &agent,
                &mapped,
                crate::grant_refusal::Layer::Agent,
            ),
        );
    }
    if !authority.pair_allowed {
        if scope.is_some_and(|scope| scope.flow_id.is_some()) {
            return reply.refuse_grant(
                crate::grant_refusal::GrantTarget::new(
                    crate::grant_refusal::Layer::Agent,
                    &agent,
                    "github",
                    Some(&handle.connection_id),
                    mapped.action,
                ),
                store.grant_cause(
                    &handle,
                    caller_principal,
                    &agent,
                    &mapped,
                    crate::grant_refusal::Layer::Agent,
                ),
            );
        }
        return reply.refuse(
            "G6",
            format!(
                "agent_grant_excludes_request{{request_kind: {}, repository: {repository}}}",
                mapped.request_kind
            ),
        );
    }
    let effect = compose_policy_effect(&authority.module_effect, authority.agent_effect.as_deref());
    if effect == "block" {
        let source = if authority.module_effect == "block" {
            "module"
        } else {
            "agent"
        };
        return reply.refuse("G6", format!("policy_blocked{{source: {source}}}"));
    }
    if effect == "ask_first" && scope.is_some_and(|scope| scope.flow_id.is_some()) {
        return reply.refuse("G6", "consent_unavailable");
    }
    let planned = super::effects::plan(&mapped);
    if planned.is_empty() || planned.len() > 6 {
        return reply.refuse("G3", "request_field_forbidden{field: body}");
    }
    let effects: Vec<Effect> = planned
        .into_iter()
        .map(|(action, _)| Effect {
            effect: action.into(),
            dispatch_attempted_at: None,
            request_id: None,
            outcome: None,
        })
        .collect();
    let claim = match store.claim(
        &agent,
        nonce,
        &mapped,
        &handle,
        claim_owner,
        &authority.baseline,
        &effects,
        effect == "ask_first",
        now,
        lease_seconds,
    ) {
        Ok(Claim::PayloadMismatch) => return reply.refuse("G4", "nonce_payload_mismatch"),
        Ok(Claim::InFlight) => return reply.refuse("G4", "nonce_in_flight"),
        Ok(claim) => claim,
        Err(code) => return reply.refuse("G7", code),
    };
    reply.gate = "G7";
    if let Claim::Replay(row) = &claim {
        reply.refusal_code = row.refusal_code.clone();
    }
    reply.claim = Some(claim);
    reply.mapped = Some(mapped);
    reply.handle = Some(handle);
    reply
}
