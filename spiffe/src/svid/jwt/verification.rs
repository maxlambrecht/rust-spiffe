//! Offline-only header and temporal policy; parse-only APIs keep their schema.

use super::{Header, JsonError, JwtSvidError, JwtVerificationError};
use jsonwebtoken::errors::ErrorKind;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

// Fixed independently of downstream time/large-dates feature unification.
const MIN_TIMESTAMP_NANOS: i128 = -377_705_116_800_000_000_000;
const MAX_TIMESTAMP_NANOS: i128 = 253_402_300_799_999_999_999;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default, deserialize_with = "present_string")]
    typ: Option<String>,
}

fn present_string<'de, D: Deserializer<'de>>(de: D) -> Result<Option<String>, D::Error> {
    String::deserialize(de).map(Some)
}

pub(super) fn parse_header(json: &[u8]) -> Result<Header, JwtSvidError> {
    let header: VerificationHeader = serde_json::from_slice(json)
        .map_err(|source| JwtSvidError::InvalidJoseHeader(JsonError::new(source)))?;
    Ok(Header {
        alg: header.alg,
        kid: header.kid,
        typ: header.typ,
    })
}

#[derive(Deserialize)]
struct NotBeforeClaim<'a> {
    // Default applies only to omission. A present null is retained for rejection.
    #[serde(default, borrow, deserialize_with = "present_raw_value")]
    nbf: Option<&'a RawValue>,
}

fn present_raw_value<'de, D: Deserializer<'de>>(de: D) -> Result<Option<&'de RawValue>, D::Error> {
    <&RawValue>::deserialize(de).map(Some)
}

pub(super) fn parse_not_before(json: &[u8]) -> Result<Option<OffsetDateTime>, JwtSvidError> {
    let claim: NotBeforeClaim<'_> =
        serde_json::from_slice(json).map_err(|_json_error| JwtSvidError::InvalidNotBefore)?;
    claim
        .nbf
        .map(|raw| numeric_date(raw).ok_or(JwtSvidError::InvalidNotBefore))
        .transpose()
}

// Convert the original JSON decimal to exact nanoseconds, without f64 rounding.
// Only numbers exactly representable at nanosecond precision in years
// -9999..=9999 are supported. JSON syntax has already been checked by RawValue.
fn numeric_date(raw: &RawValue) -> Option<OffsetDateTime> {
    let text = raw.get();
    let (negative, unsigned) = text.strip_prefix('-').map_or((false, text), |s| (true, s));
    if !unsigned.as_bytes().first()?.is_ascii_digit() {
        return None;
    }
    let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
        None => (unsigned, 0),
    };
    let fractional_digits = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let Some(last_nonzero) = mantissa
        .bytes()
        .rposition(|b| b.is_ascii_digit() && b != b'0')
    else {
        return OffsetDateTime::from_unix_timestamp_nanos(0).ok();
    };
    let significant = mantissa.get(..=last_nonzero)?;
    let trailing_zeros = mantissa
        .get(last_nonzero + 1..)?
        .bytes()
        .filter(u8::is_ascii_digit)
        .count();
    let mut coefficient = 0i128;
    for digit in significant.bytes().filter(|b| *b != b'.') {
        coefficient = coefficient
            .checked_mul(10)?
            .checked_add(i128::from(digit - b'0'))?;
    }
    let power = 9i32
        .checked_add(exponent)?
        .checked_sub(i32::try_from(fractional_digits).ok()?)?
        .checked_add(i32::try_from(trailing_zeros).ok()?)?;
    // Trailing zeros have been removed, so a negative power loses precision.
    let nanos = coefficient.checked_mul(10i128.checked_pow(u32::try_from(power).ok()?)?)?;
    let nanos = if negative {
        nanos.checked_neg()?
    } else {
        nanos
    };
    if !(MIN_TIMESTAMP_NANOS..=MAX_TIMESTAMP_NANOS).contains(&nanos) {
        return None;
    }
    OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()
}

pub(super) fn clock_timestamp(now: SystemTime) -> Result<OffsetDateTime, JwtSvidError> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_time_error| JwtSvidError::InvalidVerificationTime)?;
    let nanos = i128::try_from(elapsed.as_nanos())
        .map_err(|_time_error| JwtSvidError::InvalidVerificationTime)?;
    if nanos > MAX_TIMESTAMP_NANOS {
        return Err(JwtSvidError::InvalidVerificationTime);
    }
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_time_error| JwtSvidError::InvalidVerificationTime)
}

pub(super) fn validate_times(
    expiration: OffsetDateTime,
    not_before: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Result<(), JwtSvidError> {
    let failure = if now >= expiration {
        Some(ErrorKind::ExpiredSignature)
    } else if not_before.is_some_and(|activation| now < activation) {
        Some(ErrorKind::ImmatureSignature)
    } else {
        None
    };
    match failure {
        Some(kind) => Err(JwtSvidError::InvalidToken(JwtVerificationError::new(
            kind.into(),
        ))),
        None => Ok(()),
    }
}
