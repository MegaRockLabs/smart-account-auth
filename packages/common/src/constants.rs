#[cfg(feature = "injective")]
pub const IS_INJECTIVE: bool = true;
#[cfg(not(feature = "injective"))]
pub const IS_INJECTIVE: bool = false;

#[cfg(feature = "cosmwasm")]
pub const IS_COSMWASM: bool = true;
#[cfg(not(feature = "cosmwasm"))]
pub const IS_COSMWASM: bool = false;

#[cfg(feature = "native")]
pub const IS_NATIVE: bool = true;
#[cfg(not(feature = "native"))]
pub const IS_NATIVE: bool = false;

#[cfg(feature = "replay")]
pub const IS_REPLAY_PROTECTION_ON: bool = true;
#[cfg(not(feature = "replay"))]
pub const IS_REPLAY_PROTECTION_ON: bool = false;