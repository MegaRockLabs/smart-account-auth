// add utility methods to the `Credential` enum
mod impls;

#[cfg(feature = "storage")]
mod storage;


#[cfg(feature = "storage")]
pub use storage::{top_methods, storage_methods};

#[cfg(feature = "session")]
pub use storage::session_methods;
