use core::fmt;
use core::ops::Deref;
use base64::engine::{Engine, GeneralPurpose};
use serde::{de::{self, DeserializeOwned}, ser, Deserialize, Deserializer, Serialize};

use crate::AuthError;

#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "wasm", derive(
    saa_schema::schemars::JsonSchema
))]
#[cfg_attr(feature = "substrate", derive(
    saa_schema::scale::Encode, 
    saa_schema::scale::Decode
))]
#[cfg_attr(feature = "solana", derive(
    saa_schema::borsh::BorshSerialize, 
    saa_schema::borsh::BorshDeserialize
))]
#[cfg_attr(all(feature = "std", feature="substrate"), derive(
    saa_schema::scale_info::TypeInfo)
)]
pub struct Binary(
    #[cfg_attr(feature = "wasm", schemars(with = "String"))]
    Vec<u8>
);

impl Binary {
    /// Creates a new `Binary` containing the given data.
    pub const fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Base64 encoding engine used in conversion to/from base64.
    ///
    /// The engine adds padding when encoding and accepts strings with or
    /// without padding when decoding.
    const B64_ENGINE: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

    /// take an (untrusted) string and decode it into bytes.
    /// fails if it is not valid base64
    pub fn from_base64(encoded: &str) -> Result<Self, AuthError> {
        Self::B64_ENGINE
            .decode(encoded.as_bytes())
            .map(Binary::from)
            .map_err(|_| AuthError::generic("invalid base64"))
    }

    /// encode to base64 string (guaranteed to be success as we control the data inside).
    /// this returns normalized form (with trailing = if needed)
    pub fn to_base64(&self) -> String {
        Self::B64_ENGINE.encode(self.0.as_slice())
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn to_array<const LENGTH: usize>(&self) -> Result<[u8; LENGTH], AuthError> {
        if self.len() != LENGTH {
            return Err(AuthError::InvalidLength("Binary".to_string(), LENGTH as u16, self.len() as u16));
        }

        let mut out: [u8; LENGTH] = [0; LENGTH];
        out.copy_from_slice(&self.0);
        Ok(out)
    }
}

impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl fmt::Debug for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use an output inspired by tuples (https://doc.rust-lang.org/std/fmt/struct.Formatter.html#method.debug_tuple)
        // but with a custom implementation to avoid the need for an intemediate hex string.
        write!(f, "Binary(")?;
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

/// Just like Vec<u8>, Binary is a smart pointer to [u8].
/// This implements `*binary` for us and allows us to
/// do `&*binary`, returning a `&[u8]` from a `&Binary`.
/// With [deref coercions](https://doc.rust-lang.org/1.22.1/book/first-edition/deref-coercions.html#deref-coercions),
/// this allows us to use `&binary` whenever a `&[u8]` is required.
impl Deref for Binary {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Binary {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

// Slice
impl From<&[u8]> for Binary {
    fn from(binary: &[u8]) -> Self {
        Self(binary.to_vec())
    }
}

// Array reference
impl<const LENGTH: usize> From<&[u8; LENGTH]> for Binary {
    fn from(source: &[u8; LENGTH]) -> Self {
        Self(source.to_vec())
    }
}

// Owned array
impl<const LENGTH: usize> From<[u8; LENGTH]> for Binary {
    fn from(source: [u8; LENGTH]) -> Self {
        Self(source.into())
    }
}

impl From<Vec<u8>> for Binary {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl From<Binary> for Vec<u8> {
    fn from(original: Binary) -> Vec<u8> {
        original.0
    }
}

/// Implement `encoding::Binary == alloc::vec::Vec<u8>`
impl PartialEq<Vec<u8>> for Binary {
    fn eq(&self, rhs: &Vec<u8>) -> bool {
        // Use Vec<u8> == Vec<u8>
        self.0 == *rhs
    }
}

/// Implement `alloc::vec::Vec<u8> == encoding::Binary`
impl PartialEq<Binary> for Vec<u8> {
    fn eq(&self, rhs: &Binary) -> bool {
        // Use Vec<u8> == Vec<u8>
        *self == rhs.0
    }
}

/// Implement `Binary == &[u8]`
impl PartialEq<&[u8]> for Binary {
    fn eq(&self, rhs: &&[u8]) -> bool {
        // Use &[u8] == &[u8]
        self.as_slice() == *rhs
    }
}

/// Implement `&[u8] == Binary`
impl PartialEq<Binary> for &[u8] {
    fn eq(&self, rhs: &Binary) -> bool {
        // Use &[u8] == &[u8]
        *self == rhs.as_slice()
    }
}

/// Implement `Binary == &[u8; LENGTH]`
impl<const LENGTH: usize> PartialEq<&[u8; LENGTH]> for Binary {
    fn eq(&self, rhs: &&[u8; LENGTH]) -> bool {
        self.as_slice() == rhs.as_slice()
    }
}

/// Implement `&[u8; LENGTH] == Binary`
impl<const LENGTH: usize> PartialEq<Binary> for &[u8; LENGTH] {
    fn eq(&self, rhs: &Binary) -> bool {
        self.as_slice() == rhs.as_slice()
    }
}

/// Implement `Binary == [u8; LENGTH]`
impl<const LENGTH: usize> PartialEq<[u8; LENGTH]> for Binary {
    fn eq(&self, rhs: &[u8; LENGTH]) -> bool {
        self.as_slice() == rhs.as_slice()
    }
}

/// Implement `[u8; LENGTH] == Binary`
impl<const LENGTH: usize> PartialEq<Binary> for [u8; LENGTH] {
    fn eq(&self, rhs: &Binary) -> bool {
        self.as_slice() == rhs.as_slice()
    }
}

/// Serializes as a base64 string
impl Serialize for Binary {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_base64())
        } else {
            panic!("Binary is only intended to be used with JSON serialization for now. If you are hitting this panic please open an issue at https://github.com/CosmWasm/cosmwasm describing your use case.")
        }
    }
}

/// Deserializes as a base64 string
impl<'de> Deserialize<'de> for Binary {
    fn deserialize<D>(deserializer: D) -> Result<Binary, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Base64Visitor)
        } else {
            panic!("Binary is only intended to be used with JSON serialization for now. If you are hitting this panic please open an issue at https://github.com/CosmWasm/cosmwasm describing your use case.")
        }
    }
}



struct Base64Visitor;

impl<'de> de::Visitor<'de> for Base64Visitor {
    type Value = Binary;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("valid base64 encoded string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match Binary::from_base64(v) {
            Ok(binary) => Ok(binary),
            Err(_) => Err(E::custom(format!("invalid base64: {v}"))),
        }
    }
}



pub fn to_json_binary<T>(data: &T) -> Result<Binary, AuthError>
where
    T: Serialize + ?Sized,
{   
    serde_json_wasm::to_vec(data).map_err(|e| AuthError::generic(e.to_string())).map(Binary)
}



pub fn from_json<T: DeserializeOwned>(value: impl AsRef<[u8]>) -> Result<T, AuthError> {
    serde_json_wasm::from_slice(value.as_ref())
        .map_err(|e| AuthError::generic(e.to_string()))
}


pub fn to_json_string<T>(data: &T) -> Result<String, AuthError>
where T: Serialize + ?Sized,{
    serde_json_wasm::to_string(data).map_err(|e| AuthError::generic(e.to_string()))
}