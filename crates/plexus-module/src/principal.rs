//! Classify principals for connector access; missing, unverified, and
//! non-first-party principals are treated as untrusted and denied access.

use subc_protocol::Principal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalTrust {
    FirstParty,
    Untrusted,
}

impl PrincipalTrust {
    pub fn is_first_party(self) -> bool {
        matches!(self, Self::FirstParty)
    }
}

/// Classify the daemon-stamped bind principal before accepting a route.
/// Missing and unverified principals are never granted connector access.
pub fn trust_for_principal(principal: &Option<Principal>) -> PrincipalTrust {
    match principal {
        Some(Principal::Direct) => PrincipalTrust::FirstParty,
        Some(Principal::Reserved { module_id }) if is_first_party_module_id(module_id) => {
            PrincipalTrust::FirstParty
        }
        Some(Principal::Reserved { .. }) | Some(Principal::Unverified) | None => {
            PrincipalTrust::Untrusted
        }
    }
}

/// First-party module ids, by exact string.
///
/// This is a WIDENING gate: it decides who gets first-party standing before
/// the manifest -> ticket -> connection -> grant -> invoke chain begins, and it
/// narrows nothing. So an id missing from this list cannot leak authority; it
/// strands a legitimate caller outside the chain entirely, and the symptom is a
/// module that silently loses connector access rather than an error naming the
/// cause.
///
/// That makes module RENAMES the hazard. A rename lands in another repo, and
/// this list keeps matching the old string with nothing to indicate it has gone
/// stale. The ordering rule is the opposite of the one for route targets:
/// a dialler ships the new name first, but an allowlist is DIALLED, so
/// **every place naming a module by string must accept the new name BEFORE the
/// module starts using it**. Both names are carried across the window and the
/// old one is dropped once the flip settles.
///
/// The old name comes out only when nothing can run under it any more,
/// including a rollback binary still on the deploy path, not when the new name
/// starts working. During the window, carrying the old id is safe in a way that
/// omitting a live one is not: the daemon issues `Principal::Reserved` only for
/// modules it actually supervises, so a string no module registers is
/// unreachable rather than a widened door, while an id MISSING from this list
/// denies connector access to a legitimate caller with no error naming the
/// reason.
///
/// Note the shape this list CANNOT express: the host bridge registers
/// `prefrontal-host:<provider-id>`, a prefix with a variable suffix. Exact
/// matching can never admit it, which is deliberate — granting it standing
/// would require prefix matching, and a prefix match over an attacker-
/// influenced suffix is a much larger door than the one it opens. If the host
/// bridge ever needs connector access, that is a design question, not a string
/// to add here.
///
/// `basal` runs flows and is the only module admitted to carry a flow-stamped
/// call (see `ADMITTED_FLOW_CARRIERS` in lib.rs). Standing here only lets it
/// bind; what it may reach is still bounded by its own module grants.
///
/// `cingulate` serves the operator's permissions page and calls
/// `permissions.list` and `permissions.revoke` here. Standing only lets it
/// bind: it holds no grants, so every facade tool still refuses it.
fn is_first_party_module_id(module_id: &str) -> bool {
    matches!(
        module_id,
        "prefrontal-core" | "prefrontal-routing" | "aft" | "broca" | "basal" | "cingulate"
    )
}

pub use plexus_core::scope::principal_label as principal_key;
pub const BASAL_PRINCIPAL: &str = "reserved:basal";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_is_first_party() {
        assert_eq!(
            trust_for_principal(&Some(Principal::Direct)),
            PrincipalTrust::FirstParty
        );
    }

    /// Every first-party id must actually RESOLVE to first-party standing.
    ///
    /// Without this the suite only ever proved refusal: emptying the allowlist
    /// entirely — `is_first_party_module_id` returning `false` for everything —
    /// left the whole module suite green, because no test anywhere asserted
    /// that any id is accepted. A refusal-only suite cannot distinguish a
    /// working allowlist from one that admits nobody, which is exactly the
    /// failure a rename produces.
    #[test]
    fn every_first_party_module_id_is_accepted() {
        for module_id in [
            "prefrontal-core",
            "prefrontal-routing",
            "aft",
            "broca",
            "basal",
            "cingulate",
        ] {
            assert_eq!(
                trust_for_principal(&Some(Principal::Reserved {
                    module_id: module_id.to_string(),
                })),
                PrincipalTrust::FirstParty,
                "{module_id} must be granted first-party standing"
            );
        }
    }

    #[test]
    fn untrusted_principals_are_denied() {
        assert_eq!(trust_for_principal(&None), PrincipalTrust::Untrusted);
        assert_eq!(
            trust_for_principal(&Some(Principal::Unverified)),
            PrincipalTrust::Untrusted
        );
        assert_eq!(
            trust_for_principal(&Some(Principal::Reserved {
                module_id: "subc-mcp".to_string(),
            })),
            PrincipalTrust::Untrusted
        );
        // The pre-rename ids of prefrontal-core and prefrontal-routing. Their
        // binaries are gone from the deploy path, so nothing legitimate can
        // register them; a module that did must not inherit first-party standing.
        for retired in ["alfonso-core", "alfonso-routing"] {
            assert_eq!(
                trust_for_principal(&Some(Principal::Reserved {
                    module_id: retired.to_string(),
                })),
                PrincipalTrust::Untrusted,
                "{retired} is a retired id and must not be first-party"
            );
        }
    }

    /// Matching is EXACT, so no id that merely resembles a first-party one is
    /// admitted.
    ///
    /// The live example is the host bridge, which registers
    /// `prefrontal-host:<provider-id>` — a first-party-looking prefix with a
    /// variable suffix. Admitting it would require prefix matching, and a
    /// prefix match here would also admit anything else beginning with a
    /// first-party name, which is a far larger door than the one it opens.
    ///
    /// This is the direction a rename makes tempting: when a name is in flux it
    /// is easy to reach for `starts_with` and quietly widen the gate. The
    /// vectors below are the shapes that would then slip through.
    #[test]
    fn ids_that_merely_resemble_a_first_party_id_are_denied() {
        for module_id in [
            // `prefrontal` with no suffix: a plausible-looking id that no
            // module registers. It was briefly in the allowlist above, added
            // from a second-hand report of the rename rather than from the
            // renamed module's own source, where the real ids turned out to be
            // `prefrontal-core` and `prefrontal-routing`. Asserting it is
            // DENIED, instead of merely deleting it, means the same guess
            // cannot be re-added later without failing this test.
            "prefrontal",
            "prefrontal-host:abc123",
            "prefrontal-core-evil",
            "prefrontal\u{0}-core",
            "not-prefrontal-core",
            "aftershock",
            "broca-tui",
            "basal-worker",
            "basalx",
            "cingulate-x",
            "cingulatex",
            "Cingulate",
            "",
        ] {
            assert_eq!(
                trust_for_principal(&Some(Principal::Reserved {
                    module_id: module_id.to_string(),
                })),
                PrincipalTrust::Untrusted,
                "{module_id:?} must not be granted first-party standing"
            );
        }
    }
}
