use curve25519_dalek::{digest::Update, edwards::CompressedEdwardsY, traits::IsIdentity, EdwardsPoint, Scalar};
use sha2::Sha512;
use crate::AuthError;

pub use ed25519::Signature
;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerificationKeyBytes(pub [u8; 32]);


#[derive(Copy, Clone)]
#[allow(non_snake_case)]
pub struct VerificationKey {
    pub A_bytes: VerificationKeyBytes,
    pub minus_A: EdwardsPoint,
}



impl From<VerificationKey> for VerificationKeyBytes {
    fn from(vk: VerificationKey) -> VerificationKeyBytes {
        vk.A_bytes
    }
}

impl From<VerificationKey> for [u8; 32] {
    fn from(vk: VerificationKey) -> [u8; 32] {
        vk.A_bytes.0
    }
}

impl From<VerificationKeyBytes> for [u8; 32] {
    fn from(vb: VerificationKeyBytes) -> [u8; 32] {
        vb.0
    }
}

impl From<[u8; 32]> for VerificationKeyBytes {
    fn from(b: [u8; 32]) -> VerificationKeyBytes {
        VerificationKeyBytes(b)
    }
}

impl TryFrom<VerificationKeyBytes> for VerificationKey {
    type Error = AuthError;
    #[allow(non_snake_case)]
    fn try_from(bytes: VerificationKeyBytes) -> Result<Self, Self::Error> {
        // * `A_bytes` and `R_bytes` MUST be encodings of points `A` and `R` respectively on the
        //   twisted Edwards form of Curve25519, and non-canonical encodings MUST be accepted;
        let A = CompressedEdwardsY(bytes.0)
            .decompress()
            .ok_or(AuthError::Crypto(String::from("Mailfrom public key")))?;


        Ok(VerificationKey {
            A_bytes: bytes,
            minus_A: -A,
        })
    }
}


impl TryFrom<[u8; 32]> for VerificationKey {
    type Error = AuthError;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        VerificationKeyBytes::from(bytes).try_into().map_err(|_| AuthError::Crypto("Invalid pubkey".to_string()))
    }
}



impl VerificationKey {

    #[allow(non_snake_case)]
    pub fn verify_prehashed(&self, signature: &Signature, k: Scalar) -> Result<(), AuthError> {
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes()))
            .ok_or(AuthError::Signature("Invalid signature".into()))?;
        
        let R = CompressedEdwardsY(*signature.r_bytes())
            .decompress()
            .ok_or(AuthError::Signature("Invalid signature".into()))?;

            //       [8][s]B = [8]R + [8][k]A
        // <=>   [8]R = [8][s]B - [8][k]A
        // <=>   0 = [8](R - ([s]B - [k]A))
        // <=>   0 = [8](R - R')  where R' = [s]B - [k]A
        let R_prime = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &self.minus_A, &s);

        if (R - R_prime).mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(AuthError::Signature("Invalid signature".into()))
        }
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), AuthError> {
        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&signature.r_bytes()[..])
                .chain(&self.A_bytes.0[..])
                .chain(msg),
        );
        self.verify_prehashed(signature, k)
    }
}
