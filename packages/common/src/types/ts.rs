use core::fmt;
use saa_schema::wasm_serde;
use super::uints::Uint64;


#[wasm_serde]
#[derive(Copy, Default, Eq, PartialOrd, Ord,)]
pub struct Timestamp(Uint64);

impl Timestamp {
    /// Creates a timestamp from nanoseconds since epoch
    pub const fn from_nanos(nanos_since_epoch: u64) -> Self {
        Timestamp(Uint64::new(nanos_since_epoch))
    }

    /// Creates a timestamp from seconds since epoch
    pub const fn from_seconds(seconds_since_epoch: u64) -> Self {
        Timestamp(Uint64::new(seconds_since_epoch * 1_000_000_000))
    }

    /// Adds the given amount of days to the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result exceeds the value range of [`Timestamp`].
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub const fn plus_days(&self, addition: u64) -> Timestamp {
        self.plus_hours(addition * 24)
    }

    /// Adds the given amount of hours to the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result exceeds the value range of [`Timestamp`].
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub const fn plus_hours(&self, addition: u64) -> Timestamp {
        self.plus_minutes(addition * 60)
    }

    /// Adds the given amount of minutes to the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result exceeds the value range of [`Timestamp`].
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub const fn plus_minutes(&self, addition: u64) -> Timestamp {
        self.plus_seconds(addition * 60)
    }

    /// Adds the given amount of seconds to the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result exceeds the value range of [`Timestamp`].
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub const fn plus_seconds(&self, addition: u64) -> Timestamp {
        self.plus_nanos(addition * 1_000_000_000)
    }

    /// Adds the given amount of nanoseconds to the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result exceeds the value range of [`Timestamp`].
    #[must_use = "this returns the result of the operation, without modifying the original"]
    // no #[inline] here as this could be shared with all the callers
    pub const fn plus_nanos(&self, addition: u64) -> Timestamp {
        let nanos = self.0.strict_add(Uint64::new(addition));
        Timestamp(nanos)
    }

    /// Subtracts the given amount of days from the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result is not >= 0. I.e. times before epoch cannot be represented.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub const fn minus_days(&self, subtrahend: u64) -> Timestamp {
        self.minus_hours(subtrahend * 24)
    }

    /// Subtracts the given amount of hours from the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result is not >= 0. I.e. times before epoch cannot be represented.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub const fn minus_hours(&self, subtrahend: u64) -> Timestamp {
        self.minus_minutes(subtrahend * 60)
    }

    /// Subtracts the given amount of minutes from the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result is not >= 0. I.e. times before epoch cannot be represented.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub const fn minus_minutes(&self, subtrahend: u64) -> Timestamp {
        self.minus_seconds(subtrahend * 60)
    }

    /// Subtracts the given amount of seconds from the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result is not >= 0. I.e. times before epoch cannot be represented.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub const fn minus_seconds(&self, subtrahend: u64) -> Timestamp {
        self.minus_nanos(subtrahend * 1_000_000_000)
    }

    /// Subtracts the given amount of nanoseconds from the timestamp and
    /// returns the result. The original value remains unchanged.
    ///
    /// Panics if the result is not >= 0. I.e. times before epoch cannot be represented.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    // no #[inline] here as this could be shared with all the callers
    pub const fn minus_nanos(&self, subtrahend: u64) -> Timestamp {
        Timestamp(self.0.strict_sub(Uint64::new(subtrahend)))
    }

    /// Returns nanoseconds since epoch
    #[inline]
    pub fn nanos(&self) -> u64 {
        self.0.u64()
    }

    /// Returns seconds since epoch (truncate nanoseconds)
    #[inline]
    pub fn seconds(&self) -> u64 {
        self.0.u64() / 1_000_000_000
    }

    /// Returns nanoseconds since the last whole second (the remainder truncated
    /// by `seconds()`)
    #[inline]
    pub fn subsec_nanos(&self) -> u64 {
        self.0.u64() % 1_000_000_000
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let whole = self.seconds();
        let fractional = self.subsec_nanos();
        write!(f, "{whole}.{fractional:09}")
    }
}