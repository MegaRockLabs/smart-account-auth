use saa_common::Verifiable;


#[cfg(not(feature = "optimise"))]
mod default;
#[cfg(feature = "optimise")]
mod optimised;

#[cfg(feature = "optimise")]
pub use optimised::*;
#[cfg(not(feature = "optimise"))]
pub use default::*;




// implement for all &Credential whose enum value is Verifiable
impl<T> ReplayProtection for T  where T: Verifiable + std::ops::Deref<Target = dyn Verifiable> {}
