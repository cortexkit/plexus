use std::cell::Cell;
use std::time::Instant;

thread_local! {
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

pub(super) fn deadline() -> Option<Instant> {
    DEADLINE.with(Cell::get)
}

pub(super) fn expired() -> bool {
    deadline().is_some_and(|until| Instant::now() >= until)
}

/// Restore the caller's deadline even if a nested poll unwinds.
pub(super) fn with_deadline<R>(until: Option<Instant>, run: impl FnOnce() -> R) -> R {
    struct Restore(Option<Instant>);
    impl Drop for Restore {
        fn drop(&mut self) {
            DEADLINE.with(|slot| slot.set(self.0));
        }
    }
    let _restore = Restore(DEADLINE.with(|slot| slot.replace(until)));
    run()
}
