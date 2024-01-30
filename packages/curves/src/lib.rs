#![cfg_attr(all(feature = "substrate", not(feature = "std")), no_std)]

pub mod ed25519;
pub mod secp256k1;

#[cfg(test)]
mod tests;
pub mod utils;