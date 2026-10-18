//! Capacity held by a synchronous route request, separate from its admission.
use std::cell::RefCell;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use std::time::Instant;

pub(crate) struct RequestBudget {
    pub(crate) deadline: Instant,
    expired: std::sync::atomic::AtomicBool,
}
impl RequestBudget {
    pub(crate) fn new() -> Arc<Self> {
        Self::until(Instant::now() + plexus_core::consent_card::HELD_CALL_BUDGET)
    }
    pub(crate) fn until(deadline: Instant) -> Arc<Self> {
        Arc::new(Self {
            deadline,
            expired: std::sync::atomic::AtomicBool::new(false),
        })
    }
    pub(crate) fn expired(&self) -> bool {
        self.expired.load(std::sync::atomic::Ordering::Relaxed) || Instant::now() >= self.deadline
    }
}

struct Slot {
    budget: Arc<RequestBudget>,
    semaphore: Arc<Semaphore>,
    permit: Option<OwnedSemaphorePermit>,
}

thread_local! {
    static SLOT: RefCell<Option<Slot>> = const { RefCell::new(None) };
}

pub(crate) struct RequestSlot;
impl RequestSlot {
    pub(crate) fn enter(
        semaphore: Arc<Semaphore>,
        permit: OwnedSemaphorePermit,
        budget: Arc<RequestBudget>,
    ) -> Self {
        SLOT.with(|slot| {
            assert!(slot.borrow().is_none(), "request work slots cannot nest");
            *slot.borrow_mut() = Some(Slot {
                budget,
                semaphore,
                permit: Some(permit),
            });
        });
        Self
    }
}
impl Drop for RequestSlot {
    fn drop(&mut self) {
        SLOT.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

/// A parked consent call retains admission but does not occupy a work slot.
/// Resuming reacquires capacity before governance rechecks or dispatches it.
pub(crate) struct ConsentWaitCapacity;
impl plexus_core::governance::ConsentWaitHook for ConsentWaitCapacity {
    fn before_wait(&self) {
        SLOT.with(|state| {
            if let Some(slot) = state.borrow_mut().as_mut() {
                drop(slot.permit.take());
            }
        });
    }

    fn after_wait(&self) {
        let semaphore = SLOT.with(|state| {
            state
                .borrow()
                .as_ref()
                .filter(|slot| slot.permit.is_none())
                .map(|slot| (slot.semaphore.clone(), slot.budget.clone()))
        });
        if let Some((semaphore, budget)) = semaphore {
            let permit = crate::blocking_section(|| {
                tokio::runtime::Handle::current().block_on(tokio::time::timeout_at(
                    tokio::time::Instant::from_std(budget.deadline),
                    semaphore.acquire_owned(),
                ))
            })
            .ok()
            .and_then(Result::ok);
            if permit.is_none() {
                budget
                    .expired
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
            SLOT.with(|state| {
                state
                    .borrow_mut()
                    .as_mut()
                    .expect("request slot lives across consent wait")
                    .permit = permit;
            });
        }
    }
}
