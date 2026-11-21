//! Named crash-injection points for subprocess crash-recovery tests.
//!
//! Active only when `debug_assertions` are enabled and `LDK_WALLET_CRASH_AT`
//! matches `name`. Calls `std::process::abort()` so no `Drop` handlers or
//! cleanup code run in the child process.

#[cfg(debug_assertions)]
pub(crate) fn maybe_crash(name: &'static str) {
    if std::env::var("LDK_WALLET_CRASH_AT").ok().as_deref() == Some(name) {
        std::process::abort();
    }
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub(crate) fn maybe_crash(_name: &'static str) {}
