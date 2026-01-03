use super::builder::ResourceLimits;
use super::errors::{LimitKind, MetricsErrorKind, X509SourceError};
use super::metrics::MetricsRecorder;
use crate::workload_api::x509_context::X509Context;
use crate::x509_source::types::SvidPicker;
use std::sync::Arc;

pub(super) fn validate_limits(
    ctx: &X509Context,
    limits: ResourceLimits,
) -> Result<(), X509SourceError> {
    if let Some(max_svids) = limits.max_svids {
        let actual = ctx.svids().len();
        if actual > max_svids {
            return Err(X509SourceError::ResourceLimitExceeded {
                kind: LimitKind::MaxSvids,
                limit: max_svids,
                actual,
            });
        }
    }

    if let Some(max_bundles) = limits.max_bundles {
        let actual = ctx.bundle_set().len();
        if actual > max_bundles {
            return Err(X509SourceError::ResourceLimitExceeded {
                kind: LimitKind::MaxBundles,
                limit: max_bundles,
                actual,
            });
        }
    }

    if let Some(max_bundle_der_bytes) = limits.max_bundle_der_bytes {
        for (_, bundle) in ctx.bundle_set().iter() {
            // Definition: sum of DER bytes of all authority certificates in the bundle.
            let actual: usize = bundle
                .authorities()
                .iter()
                .map(|cert| cert.as_bytes().len())
                .sum();

            if actual > max_bundle_der_bytes {
                return Err(X509SourceError::ResourceLimitExceeded {
                    kind: LimitKind::MaxBundleDerBytes,
                    limit: max_bundle_der_bytes,
                    actual,
                });
            }
        }
    }

    Ok(())
}

/// Validates resource limits and records the appropriate metric if a limit is exceeded.
///
/// This is the single authoritative function for limit validation and metric recording.
/// It ensures that limit violations are recorded exactly once with the correct metric kind.
///
/// # Arguments
///
/// * `ctx` - The X.509 context to validate
/// * `limits` - The resource limits to enforce
/// * `metrics` - Optional metrics recorder for recording limit violations
///
/// # Returns
///
/// Returns `Ok(())` if all limits are satisfied, or `Err(X509SourceError::ResourceLimitExceeded)`
/// if any limit is exceeded. When a limit is exceeded, the corresponding metric is recorded
/// (e.g., `LimitMaxSvids`, `LimitMaxBundles`, `LimitMaxBundleDerBytes`).
pub(super) fn validate_limits_and_record_metric(
    ctx: &X509Context,
    limits: ResourceLimits,
    metrics: Option<&dyn MetricsRecorder>,
) -> Result<(), X509SourceError> {
    if let Err(e) = validate_limits(ctx, limits) {
        if let X509SourceError::ResourceLimitExceeded { kind, .. } = &e {
            if let Some(m) = metrics {
                m.record_error(metric_kind_for_limit(*kind));
            }
        }
        return Err(e);
    }
    Ok(())
}

/// Maps a `LimitKind` to the corresponding `MetricsErrorKind` for limit violations.
///
/// This is the single authoritative mapping used throughout the codebase to ensure
/// consistent metric recording for limit violations.
pub(super) fn metric_kind_for_limit(kind: LimitKind) -> MetricsErrorKind {
    match kind {
        LimitKind::MaxSvids => MetricsErrorKind::LimitMaxSvids,
        LimitKind::MaxBundles => MetricsErrorKind::LimitMaxBundles,
        LimitKind::MaxBundleDerBytes => MetricsErrorKind::LimitMaxBundleDerBytes,
    }
}

/// Selects an SVID from the context using the picker (if provided) or default selection.
///
/// This is the single authoritative function for SVID selection, ensuring consistent
/// logic across validation, health checks, and SVID retrieval.
///
/// Returns `Some(Arc<X509Svid>)` if a valid SVID can be selected, `None` otherwise.
pub(super) fn select_svid(
    ctx: &X509Context,
    picker: Option<&dyn SvidPicker>,
) -> Option<Arc<crate::X509Svid>> {
    if let Some(p) = picker {
        // Picker must return a valid index that maps to an actual SVID.
        p.pick_svid(ctx.svids())
            .and_then(|idx| ctx.svids().get(idx))
            .cloned()
    } else {
        ctx.default_svid().cloned()
    }
}

/// Validates an X.509 context for acceptability (limits and SVID selection).
///
/// This is the single authoritative function for context validation used in both
/// initial sync and steady-state updates. It ensures consistent validation logic
/// and correct metric recording.
pub(super) fn validate_context(
    ctx: &X509Context,
    picker: Option<&dyn SvidPicker>,
    limits: ResourceLimits,
    metrics: Option<&dyn MetricsRecorder>,
) -> Result<(), X509SourceError> {
    // Validate limits and record specific limit metrics if exceeded.
    validate_limits_and_record_metric(ctx, limits, metrics)?;

    // Ensure the context is usable for callers (picker or default can select).
    if select_svid(ctx, picker).is_none() {
        if let Some(m) = metrics {
            m.record_error(MetricsErrorKind::NoSuitableSvid);
        }
        return Err(X509SourceError::NoSuitableSvid);
    }

    Ok(())
}
