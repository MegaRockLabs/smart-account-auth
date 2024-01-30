use digest::generic_array::GenericArray;
use digest::consts::U32;
use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Reset, Update};

/// The 256-bits identity container
#[derive(Clone, Default)]
pub struct Identity256 {
    array: GenericArray<u8, U32>,
}

impl Update for Identity256 {
    fn update(&mut self, hash: &[u8]) {
        assert_eq!(hash.as_ref().len(), 32);
        self.array = *GenericArray::from_slice(hash);
    }
}
impl OutputSizeUser for Identity256 {
    type OutputSize = U32;
}
impl FixedOutput for Identity256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        *out = self.array;
    }
}
impl HashMarker for Identity256 {}
impl Reset for Identity256 {
    fn reset(&mut self) {
        *self = Self::default();
    }
}

