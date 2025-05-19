use core::{fmt, ops::{Add, Sub,}};
use saa_schema::saa_str_struct;
use serde::{de, ser, Deserialize, Deserializer, Serialize};


#[saa_str_struct]
pub struct Uint64(#[cfg_attr(feature = "wasm", schemars(with = "String"))]pub(crate) u64);


#[saa_str_struct]
pub struct Uint128(#[cfg_attr(feature = "wasm", schemars(with = "String"))] pub(crate) u128);



impl Uint64 {

    pub const MAX: Self = Self(u64::MAX);
    pub const MIN: Self = Self(u64::MIN);

    /// Creates a Uint64(value).
    ///
    /// This method is less flexible than `from` but can be called in a const context.
    pub const fn new(value: u64) -> Self {
        Uint64(value)
    }

    /// Creates a Uint64(0)
    #[inline]
    pub const fn zero() -> Self {
        Uint64(0)
    }

    /// Creates a Uint64(1)
    #[inline]
    pub const fn one() -> Self {
        Self(1)
    }

    /// Returns a copy of the internal data
    pub const fn u64(&self) -> u64 {
        self.0
    }


    /// Strict integer addition. Computes `self + rhs`, panicking if overflow occurred.
    ///
    /// This is the same as [`Uint64::add`] but const.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub const fn strict_add(self, rhs: Self) -> Self {
        match self.0.checked_add(rhs.u64()) {
            None => panic!("attempt to add with overflow"),
            Some(sum) => Self(sum),
        }
    }

    /// Strict integer subtraction. Computes `self - rhs`, panicking if overflow occurred.
    ///
    /// This is the same as [`Uint64::sub`] but const.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub const fn strict_sub(self, other: Self) -> Self {
        match self.0.checked_sub(other.u64()) {
            None => panic!("attempt to subtract with overflow"),
            Some(diff) => Self(diff),
        }
    }

}


impl Uint128 {
    pub const MAX: Self = Self(u128::MAX);
    pub const MIN: Self = Self(u128::MIN);

    /// Creates a Uint128(value).
    ///
    /// This method is less flexible than `from` but can be called in a const context.
    pub const fn new(value: u128) -> Self {
        Uint128(value)
    }

    /// Creates a Uint128(0)
    #[inline]
    pub const fn zero() -> Self {
        Uint128(0)
    }

    /// Creates a Uint128(1)
    #[inline]
    pub const fn one() -> Self {
        Self(1)
    }

    /// Returns a copy of the internal data
    pub const fn u128(&self) -> u128 {
        self.0
    }

    /// Returns a copy of the number as big endian bytes.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub const fn to_be_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// Returns a copy of the number as little endian bytes.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub const fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

     /// Strict integer addition. Computes `self + rhs`, panicking if overflow occurred.
    ///
    /// This is the same as [`Uint128::add`] but const.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub const fn strict_add(self, rhs: Self) -> Self {
        match self.0.checked_add(rhs.u128()) {
            None => panic!("attempt to add with overflow"),
            Some(sum) => Self(sum),
        }
    }

    /// Strict integer subtraction. Computes `self - rhs`, panicking if overflow occurred.
    ///
    /// This is the same as [`Uint128::sub`] but const.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub const fn strict_sub(self, other: Self) -> Self {
        match self.0.checked_sub(other.u128()) {
            None => panic!("attempt to subtract with overflow"),
            Some(diff) => Self(diff),
        }
    }

}




// uint to Uint
impl From<u64> for Uint64 {
    fn from(val: u64) -> Self {
        Uint64(val)
    }
}


impl From<Uint64> for String {
    fn from(original: Uint64) -> Self {
        original.to_string()
    }
}

impl From<Uint64> for u64 {
    fn from(original: Uint64) -> Self {
        original.0
    }
}

impl fmt::Display for Uint64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Uint128> for String {
    fn from(original: Uint128) -> Self {
        original.to_string()
    }
}

impl From<Uint128> for u128 {
    fn from(original: Uint128) -> Self {
        original.0
    }
}

impl fmt::Display for Uint128 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}


impl Add<Uint64> for Uint64 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.strict_add(rhs)
    }
}

impl Sub<Uint64> for Uint64 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.strict_sub(rhs)
    }
}

impl Add<Uint128> for Uint128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.strict_add(rhs)
    }
}

impl Sub<Uint128> for Uint128 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.strict_sub(rhs)
    }
}


impl Serialize for Uint64 {
    /// Serializes as an integer string using base 10
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Uint64 {
    /// Deserialized from an integer string using base 10
    fn deserialize<D>(deserializer: D) -> Result<Uint64, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Uint64Visitor)
    }
}


impl Serialize for Uint128 {
    /// Serializes as an integer string using base 10
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Uint128 {
    /// Deserialized from an integer string using base 10
    fn deserialize<D>(deserializer: D) -> Result<Uint128, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Uint128Visitor)
    }
}




struct Uint64Visitor;

impl<'de> de::Visitor<'de> for Uint64Visitor {
    type Value = Uint64;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("string-encoded integer")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match v.parse::<u64>() {
            Ok(u) => Ok(Uint64(u)),
            Err(e) => Err(E::custom(format!("invalid Uint64 '{v}' - {e}"))),
        }
    }
}

impl<A> core::iter::Sum<A> for Uint64
where
    Self: Add<A, Output = Self>,
{
    fn sum<I: Iterator<Item = A>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}


struct Uint128Visitor;

impl<'de> de::Visitor<'de> for Uint128Visitor {
    type Value = Uint128;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("string-encoded integer")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match v.parse::<u128>() {
            Ok(u) => Ok(Uint128(u)),
            Err(e) => Err(E::custom(format!("invalid Uint128 '{v}' - {e}"))),
        }
    }
}