//! Crate-internal observability macros.
//!
//! These macros abstract over `tracing` vs `log`.

#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! log_debug {
    ($($arg:tt)*) => { tracing::debug!($($arg)*); };
}

#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! log_debug {
    ($($arg:tt)*) => { log::debug!($($arg)*); };
}

#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! log_info {
    ($($arg:tt)*) => { tracing::info!($($arg)*); };
}

#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! log_info {
    ($($arg:tt)*) => { log::info!($($arg)*); };
}

#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! log_warn {
    ($($arg:tt)*) => { tracing::warn!($($arg)*); };
}
#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! log_warn {
    ($($arg:tt)*) => { log::warn!($($arg)*); };
}

#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! log_error {
    ($($arg:tt)*) => { tracing::error!($($arg)*); };
}
#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! log_error {
    ($($arg:tt)*) => { log::error!($($arg)*); };
}

pub(crate) use log_debug;
#[allow(unused_imports)]
pub(crate) use log_error;
pub(crate) use log_info;
pub(crate) use log_warn;
