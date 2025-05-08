mod credential;

#[cfg(feature = "storage")]
mod data;

#[cfg(feature = "storage")]
pub mod storage;

// re-export the next for beeter DX
#[cfg(feature = "storage")]
pub use storage::{verify_signed, verify_caller};

#[cfg(feature = "replay")]
pub use storage::verify_signed_actions;