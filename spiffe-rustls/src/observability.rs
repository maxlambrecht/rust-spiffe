//! Crate-internal observability macros.
//!
//! Behavior:
//! - `tracing` feature => emit `tracing::*` events (preferred when enabled)
//! - `logging` feature (without `tracing`) => emit `log::*` records
//! - Neither enabled => macros consume variables via `format_args!` but produce no output
//!
//! This ensures that variables passed to logging macros are always consumed,
//! preventing `unused_variable` warnings when observability features are disabled.

#[allow(unused_macros)]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        #[cfg(feature = "tracing")]
        {
            tracing::debug!($($arg)*);
        }
        #[cfg(all(not(feature = "tracing"), feature = "logging"))]
        {
            log::debug!($($arg)*);
        }
        #[cfg(not(any(feature = "tracing", feature = "logging")))]
        {
            let _ = format_args!($($arg)*);
        }
    };
}

#[allow(unused_macros)]
macro_rules! log_info {
    ($($arg:tt)*) => {
        #[cfg(feature = "tracing")]
        {
            tracing::info!($($arg)*);
        }
        #[cfg(all(not(feature = "tracing"), feature = "logging"))]
        {
            log::info!($($arg)*);
        }
        #[cfg(not(any(feature = "tracing", feature = "logging")))]
        {
            let _ = format_args!($($arg)*);
        }
    };
}

#[allow(unused_macros)]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        #[cfg(feature = "tracing")]
        {
            tracing::warn!($($arg)*);
        }
        #[cfg(all(not(feature = "tracing"), feature = "logging"))]
        {
            log::warn!($($arg)*);
        }
        #[cfg(not(any(feature = "tracing", feature = "logging")))]
        {
            let _ = format_args!($($arg)*);
        }
    };
}

#[allow(unused_macros)]
macro_rules! log_error {
    ($($arg:tt)*) => {
        #[cfg(feature = "tracing")]
        {
            tracing::error!($($arg)*);
        }
        #[cfg(all(not(feature = "tracing"), feature = "logging"))]
        {
            log::error!($($arg)*);
        }
        #[cfg(not(any(feature = "tracing", feature = "logging")))]
        {
            let _ = format_args!($($arg)*);
        }
    };
}

pub(crate) use log_debug;
pub(crate) use log_error;
pub(crate) use log_info;
pub(crate) use log_warn;
