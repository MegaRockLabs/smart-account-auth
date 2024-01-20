use macros_proto;


pub use macros_proto::wasm_serde;

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}



pub use scale;
pub use scale_info;
pub use borsh;
pub use serde;
pub use schemars;