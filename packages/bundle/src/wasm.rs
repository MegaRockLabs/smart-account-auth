// add utility methods to the `Credential` enum
mod impls;

#[cfg(feature = "session")]
mod session;

#[cfg(feature = "storage")]
mod storage;


#[cfg(feature = "storage")]
pub use storage::{top_methods, storage_methods};
