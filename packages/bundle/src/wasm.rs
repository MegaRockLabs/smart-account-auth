// add utility methods to the `Credential` enum
mod impls;

#[cfg(feature = "session")]
mod session;

#[cfg(feature = "storage")]
mod store;


#[cfg(feature = "storage")]
pub use store::{
    verify_caller, verify_signed, 
    save_credentials, has_natives,
    storage
};

#[cfg(feature = "replay")]
pub use store::replay::verify_signed_actions;

