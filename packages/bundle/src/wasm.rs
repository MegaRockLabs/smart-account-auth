#[cfg(feature = "types")]
pub use saa_common::wasm as cosmwasm_std;

impl From<&saa_common::wasm::MessageInfo> for crate::Caller {
    fn from(info: &saa_common::wasm::MessageInfo) -> Self {
        crate::Caller(info.sender.to_string())
    }
}