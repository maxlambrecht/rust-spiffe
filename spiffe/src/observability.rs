//! Crate-internal observability macros.
//!
//! Precedence:
//! 1) `tracing` feature => emit `tracing::*` events
//! 2) `logging` feature => emit `log::*` records
//! 3) neither enabled => no-op (but still evaluates format args)

#[allow(unused_macros)]
macro_rules! log_debug {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        { tracing::debug!($($arg)*); }

        #[cfg(all(not(feature = "tracing"), feature = "logging"))]
        { log::debug!($($arg)*); }

        #[cfg(all(not(feature = "tracing"), not(feature = "logging")))]
        { let _ = format_args!($($arg)*); }
    }};
}

#[allow(unused_macros)]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        { tracing::info!($($arg)*); }

        #[cfg(all(not(feature = "tracing"), feature = "logging"))]
        { log::info!($($arg)*); }

        #[cfg(all(not(feature = "tracing"), not(feature = "logging")))]
        { let _ = format_args!($($arg)*); }
    }};
}

#[allow(unused_macros)]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        { tracing::warn!($($arg)*); }

        #[cfg(all(not(feature = "tracing"), feature = "logging"))]
        { log::warn!($($arg)*); }

        #[cfg(all(not(feature = "tracing"), not(feature = "logging")))]
        { let _ = format_args!($($arg)*); }
    }};
}

#[allow(unused_macros)]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        { tracing::error!($($arg)*); }

        #[cfg(all(not(feature = "tracing"), feature = "logging"))]
        { log::error!($($arg)*); }

        #[cfg(all(not(feature = "tracing"), not(feature = "logging")))]
        { let _ = format_args!($($arg)*); }
    }};
}

pub(crate) use log_debug;
pub(crate) use log_error;
pub(crate) use log_info;
pub(crate) use log_warn;
