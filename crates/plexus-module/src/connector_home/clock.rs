#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn milliseconds() -> Option<u64> {
    use rustix::time::{clock_gettime, ClockId};
    #[cfg(target_os = "linux")]
    const CLOCK: ClockId = ClockId::Boottime;
    #[cfg(target_os = "macos")]
    const CLOCK: ClockId = ClockId::Monotonic;

    let time = clock_gettime(CLOCK);
    let seconds = u64::try_from(time.tv_sec).ok()?;
    let nanos = u64::try_from(time.tv_nsec).ok()?;
    seconds.checked_mul(1000)?.checked_add(nanos / 1_000_000)
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub(super) fn milliseconds() -> Option<u64> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetTickCount64() -> u64;
    }
    // SAFETY: GetTickCount64 takes no parameters and returns the current clock value.
    Some(unsafe { GetTickCount64() })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(super) fn milliseconds() -> Option<u64> {
    None
}
