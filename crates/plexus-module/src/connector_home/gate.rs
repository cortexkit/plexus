use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{watch, Notify};

const MIN_LEG_WINDOW: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Deserialize)]
pub(super) struct Notice {
    pub(super) seq: u64,
    pub(super) gen: u64,
    pub(super) holding: bool,
    issued_at_ms: u64,
    valid_for_ms: u64,
    #[serde(default)]
    pub(super) handback: bool,
}

impl Notice {
    fn deadline(self) -> Option<u64> {
        self.issued_at_ms.checked_add(self.valid_for_ms)
    }

    fn remaining(self, now: u64) -> Option<u64> {
        self.deadline()?.checked_sub(now).filter(|&ms| ms != 0)
    }
}

#[derive(Default)]
struct State {
    legacy: bool,
    known: bool,
    notice: Option<Notice>,
    highest_received_seq: Option<u64>,
    confirmed: bool,
    in_flight: usize,
    yield_pending: bool,
    yield_attempt: Option<(u64, u64)>,
    unsettled_yield_after: Option<u64>,
    transferred_gen: Option<u64>,
}

impl State {
    fn remaining(&self, now: Option<u64>) -> Option<u64> {
        let n = self.notice?;
        if !self.confirmed || !n.holding || self.transferred_gen.is_some_and(|gen| n.gen <= gen) {
            return None;
        }
        n.remaining(now?)
    }

    fn admission_window(&self, now: Option<u64>) -> Option<Duration> {
        if self.notice?.handback || self.yield_pending {
            return None;
        }
        self.remaining(now).map(Duration::from_millis)
    }
}

pub(super) struct Gate {
    state: Mutex<State>,
    now: Box<dyn Fn() -> Option<u64> + Send + Sync>,
    decision: watch::Sender<bool>,
    #[cfg(test)]
    yield_progress: watch::Sender<YieldProgress>,
    pub(super) drained: Notify,
}

#[cfg(test)]
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct YieldProgress {
    pub confirmed_seq: Option<u64>,
    pub in_flight: bool,
}

impl Gate {
    pub(super) fn new(legacy: bool, now: impl Fn() -> Option<u64> + Send + Sync + 'static) -> Self {
        Self {
            state: Mutex::new(State {
                legacy,
                ..State::default()
            }),
            now: Box::new(now),
            decision: watch::channel(false).0,
            #[cfg(test)]
            yield_progress: watch::channel(YieldProgress::default()).0,
            drained: Notify::new(),
        }
    }

    fn publish(&self, state: &State) {
        self.publish_decision(state.admission_window((self.now)()).is_some());
        #[cfg(test)]
        self.yield_progress.send_if_modified(|progress| {
            let next = YieldProgress {
                confirmed_seq: state
                    .notice
                    .filter(|_| state.confirmed)
                    .map(|notice| notice.seq),
                in_flight: state.yield_attempt.is_some(),
            };
            let changed = *progress != next;
            *progress = next;
            changed
        });
    }

    #[cfg(test)]
    pub(super) fn yield_progress(&self) -> watch::Receiver<YieldProgress> {
        self.yield_progress.subscribe()
    }

    fn publish_decision(&self, admitted: bool) {
        self.decision.send_if_modified(|held| {
            let changed = *held != admitted;
            *held = admitted;
            changed
        });
    }

    pub(super) fn decisions(&self) -> watch::Receiver<bool> {
        self.decision.subscribe()
    }

    pub(super) fn legacy(&self) -> bool {
        self.state.lock().unwrap().legacy
    }

    pub(super) fn enable_legacy(&self, held: bool) {
        self.state.lock().unwrap().legacy = true;
        self.legacy_decision(held);
    }

    pub(super) fn legacy_decision(&self, held: bool) {
        if self.state.lock().unwrap().legacy {
            self.publish_decision(held);
        }
    }

    pub(super) fn held(&self) -> bool {
        let state = self.state.lock().unwrap();
        let held = state.admission_window((self.now)()).is_some();
        if !state.legacy {
            self.publish_decision(held);
        }
        held
    }

    pub(super) fn refusal_state(&self) -> &'static str {
        if self.state.lock().unwrap().known {
            "not_held"
        } else {
            "unknown"
        }
    }

    pub(super) fn status(&self) -> Value {
        let state = self.state.lock().unwrap();
        let remaining = state.remaining((self.now)());
        json!({
            "holding": remaining.is_some(),
            "gen": state.notice.map(|n| n.gen),
            "deadline_in_ms": state.notice.and_then(|n| n.deadline()).zip((self.now)()).map(|(deadline, now)| deadline.saturating_sub(now)),
            "handback": state.notice.is_some_and(|n| n.handback),
            "yield_pending": state.yield_pending,
        })
    }

    pub(super) fn receive(&self, notice: Notice) {
        let mut state = self.state.lock().unwrap();
        state.known = true;
        state.highest_received_seq = Some(
            state
                .highest_received_seq
                .map_or(notice.seq, |seq| seq.max(notice.seq)),
        );
        // A normal renewal of the same generation need not interrupt service
        // while its acknowledgement is in flight. Other changes fence at once.
        state.confirmed = state.confirmed
            && state.notice.is_some_and(|previous| {
                previous.gen == notice.gen
                    && previous.seq < notice.seq
                    && previous.holding
                    && notice.holding
                    && !previous.handback
                    && !notice.handback
            });
        state.notice = Some(notice);
        self.publish(&state);
    }

    pub(super) fn confirm(&self, notice: Notice) {
        let mut state = self.state.lock().unwrap();
        state.confirmed = true;
        if notice.holding
            && !notice.handback
            && state.yield_attempt.is_none()
            && state
                .unsettled_yield_after
                .is_none_or(|seq| notice.seq > seq)
        {
            state.yield_pending = false;
            state.unsettled_yield_after = None;
        }
        self.publish(&state);
    }

    pub(super) fn disconnect(&self) {
        let mut state = self.state.lock().unwrap();
        state.notice = None;
        state.highest_received_seq = None;
        state.confirmed = false;
        state.yield_pending = false;
        state.yield_attempt = None;
        state.unsettled_yield_after = None;
        if !state.legacy {
            self.publish(&state);
        }
    }

    pub(super) fn wait_for_yield(&self) -> Option<u64> {
        let mut state = self.state.lock().unwrap();
        self.publish(&state);
        let n = state.notice?;
        if !state.confirmed
            || !n.handback
            || !n.holding
            || state.yield_pending
            || state.transferred_gen.is_some_and(|gen| n.gen <= gen)
            || (state.in_flight != 0 && n.remaining((self.now)()?).is_some())
        {
            return None;
        }
        state.yield_attempt = Some((n.seq, n.gen));
        state.yield_pending = true;
        Some(n.gen)
    }

    pub(super) fn finish_yield(&self, yielded: Option<bool>) {
        let mut state = self.state.lock().unwrap();
        let Some((seq, gen)) = state.yield_attempt.take() else {
            return;
        };
        if yielded == Some(true) {
            state.transferred_gen = Some(gen.max(state.transferred_gen.unwrap_or(0)));
        }
        // A renewal may arrive before the unary yield reply on the same route.
        state.yield_pending = match yielded {
            Some(true) => false,
            Some(false) => {
                !state.confirmed
                    || !state
                        .notice
                        .is_some_and(|n| n.seq > seq && n.holding && !n.handback)
            }
            None => {
                // Our acknowledgment of a lease notice can complete after the
                // unresolved yield reply, even when that notice reached us
                // before the yield. Fence at the highest notice received so
                // far, so confirming that earlier notice cannot reopen
                // admission; only a notice with a later seq can.
                state.unsettled_yield_after = Some(state.highest_received_seq.unwrap_or(seq));
                true
            }
        };
        self.publish(&state);
    }

    pub(super) fn begin(self: &Arc<Self>) -> Option<(Permit, Duration)> {
        let mut state = self.state.lock().unwrap();
        let remaining = state.admission_window((self.now)())?;
        if remaining < MIN_LEG_WINDOW {
            return None;
        }
        let generation = state.notice?.gen;
        state.in_flight += 1;
        Some((
            Permit {
                gate: self.clone(),
                _generation: generation,
            },
            remaining,
        ))
    }
}

pub(crate) struct Permit {
    gate: Arc<Gate>,
    // Keep the generation checked at admission with the leg until it settles.
    _generation: u64,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap();
        state.in_flight -= 1;
        if state.in_flight == 0 {
            self.gate.drained.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_yield_cannot_be_cleared_by_an_ack_for_an_earlier_notice() {
        let gate = Arc::new(Gate::new(false, || Some(100_000)));
        let handback = Notice {
            seq: 3,
            gen: 1,
            holding: true,
            issued_at_ms: 100_000,
            valid_for_ms: 60_000,
            handback: true,
        };
        gate.receive(handback);
        gate.confirm(handback);
        assert_eq!(gate.wait_for_yield(), Some(1));
        let renewal = Notice {
            seq: 4,
            handback: false,
            ..handback
        };
        gate.receive(renewal);
        gate.finish_yield(None);
        gate.confirm(renewal);
        assert!(
            gate.begin().is_none(),
            "an old notice's ACK must not reopen admission"
        );

        let fresh = Notice { seq: 5, ..renewal };
        gate.receive(fresh);
        assert!(
            gate.begin().is_none(),
            "the fresh notice still needs an ACK"
        );
        gate.confirm(fresh);
        assert!(gate.begin().is_some());
    }
}
