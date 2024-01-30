#![cfg_attr(all(feature = "substrate", not(feature = "std")), no_std)]

pub mod evm;
pub mod cosmos;
pub mod caller;

#[cfg(test)]
mod tests;