//! Capacity held by a synchronous route request, separate from its admission.
use std::cell::RefCell;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct Slot {
    semaphore: Arc<Semaphore>,
    permit: Option<OwnedSemaphorePermit>,
}

thread_local! {
    static SLOT: RefCell<Option<Slot>> = const { RefCell::new(None) };
}

pub(crate) struct RequestSlot;
impl RequestSlot {
    pub(crate) fn enter(semaphore: Arc<Semaphore>, permit: OwnedSemaphorePermit) -> Self {
        SLOT.with(|slot| {
            assert!(slot.borrow().is_none(), "request work slots cannot nest");
            *slot.borrow_mut() = Some(Slot {
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
                .map(|slot| slot.semaphore.clone())
        });
        if let Some(semaphore) = semaphore {
            let permit = crate::blocking_section(|| {
                tokio::runtime::Handle::current().block_on(semaphore.acquire_owned())
            })
            .expect("request semaphore is never closed");
            SLOT.with(|state| {
                state
                    .borrow_mut()
                    .as_mut()
                    .expect("request slot lives across consent wait")
                    .permit = Some(permit);
            });
        }
    }
}
