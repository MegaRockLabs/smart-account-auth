use std::cmp::Ordering;
use saa_schema::{saa_type, strum_macros::Display};
use super::timestamp::Timestamp;
use crate::AuthError;




#[saa_type]
#[derive(Display)]
pub enum Expiration {
    /// AtHeight will expire when `env.block.height` >= height
    #[strum(to_string = "expiration height: {0}")]
    AtHeight(u64),
    /// AtTime will expire when `env.block.time` >= time
    #[strum(to_string = "expiration time: {0}")]
    AtTime(Timestamp),
    /// Never will never expire. Used to express the empty variant
    #[strum(to_string = "expiration: never")]
    Never {},
}


/// The default (empty value) is to never expire
impl Default for Expiration {
    fn default() -> Self {
        Expiration::Never {}
    }
}



/// Duration is a delta of time. You can add it to a BlockInfo or Expiration to
/// move that further in the future. Note that an height-based Duration and
/// a time-based Expiration cannot be combined
#[saa_type]
#[derive(Display, Copy)]
pub enum Duration {
    /// Height in blocks
    #[strum(to_string = "height: {0}")]
    Height(u64),
    /// Time in seconds
    #[strum(to_string = "time: {0}")]
    Time(u64),
}



#[cfg(feature = "wasm")]
impl Expiration {
    pub fn is_expired(&self, block: &crate::wasm::BlockInfo) -> bool {
        match self {
            Expiration::AtHeight(height) => block.height >= *height,
            Expiration::AtTime(time) => block.time.seconds() >= time.seconds(),
            Expiration::Never {} => false,
        }
    }
}


impl std::ops::Add<Duration> for Expiration {
    type Output = Result<Expiration, AuthError>;

    fn add(self, duration: Duration) -> Result<Expiration, AuthError> {
        match (self, duration) {
            (Expiration::AtTime(t), Duration::Time(delta)) => {
                Ok(Expiration::AtTime(t.plus_seconds(delta)))
            }
            (Expiration::AtHeight(h), Duration::Height(delta)) => {
                Ok(Expiration::AtHeight(h + delta))
            }
            (Expiration::Never {}, _) => Ok(Expiration::Never {}),
            _ => Err(AuthError::generic("Cannot add height and time")),
        }
    }
}


impl PartialOrd for Expiration {
    fn partial_cmp(&self, other: &Expiration) -> Option<Ordering> {
        match (self, other) {
            // compare if both height or both time
            (Expiration::AtHeight(h1), Expiration::AtHeight(h2)) => Some(h1.cmp(h2)),
            (Expiration::AtTime(t1), Expiration::AtTime(t2)) => Some(t1.cmp(t2)),
            // if at least one is never, we can compare with anything
            (Expiration::Never {}, Expiration::Never {}) => Some(Ordering::Equal),
            (Expiration::Never {}, _) => Some(Ordering::Greater),
            (_, Expiration::Never {}) => Some(Ordering::Less),
            // if they are mis-matched finite ends, no compare possible
            _ => None,
        }
    }
}