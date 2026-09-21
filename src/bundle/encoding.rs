//! Read-only views of the byte encodings of Sapling descriptions and bundles.
//!
//! Each trait is implemented by the point type ([`SpendDescription`], …) and its
//! compressed counterpart ([`SpendDescriptionBytes`], …), so code that only needs
//! encodings (serialization, ZIP-244 digests, v4 sighash) is written once for both.

use zcash_note_encryption::{EphemeralKeyBytes, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE};

use super::{
    Authorization, Bundle, BundleBytes, OutputDescription, OutputDescriptionBytes,
    SpendDescription, SpendDescriptionBytes,
};
use crate::{note::ExtractedNoteCommitment, Nullifier};

/// The byte encodings of a Spend description.
pub trait SpendDescriptionEncoding<A: Authorization> {
    /// `cv`, as encoded.
    fn cv_bytes(&self) -> [u8; 32];
    /// The root of the Sapling commitment tree the spend proves membership in.
    fn anchor(&self) -> &bls12_381::Scalar;
    /// The nullifier of the input note.
    fn nullifier(&self) -> &Nullifier;
    /// `rk`, as encoded.
    fn rk_bytes(&self) -> [u8; 32];
    /// The proof for the spend.
    fn zkproof(&self) -> &A::SpendProof;
    /// The spend authorization signature.
    fn spend_auth_sig(&self) -> &A::AuthSig;
}

/// The byte encodings of an Output description.
pub trait OutputDescriptionEncoding<Proof> {
    /// `cv`, as encoded.
    fn cv_bytes(&self) -> [u8; 32];
    /// The commitment to the output note.
    fn cmu(&self) -> &ExtractedNoteCommitment;
    /// `epk`, as encoded.
    fn ephemeral_key(&self) -> &EphemeralKeyBytes;
    /// The encrypted note ciphertext.
    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE];
    /// The outgoing ciphertext.
    fn out_ciphertext(&self) -> &[u8; OUT_CIPHERTEXT_SIZE];
    /// The proof for the output.
    fn zkproof(&self) -> &Proof;
}

/// The byte encodings of a Sapling bundle.
pub trait BundleEncoding<A: Authorization, V> {
    /// This tier's Spend description.
    type Spend: SpendDescriptionEncoding<A>;
    /// This tier's Output description.
    type Output: OutputDescriptionEncoding<A::OutputProof>;

    /// The bundle's spends.
    fn shielded_spends(&self) -> &[Self::Spend];
    /// The bundle's outputs.
    fn shielded_outputs(&self) -> &[Self::Output];
    /// The net value moved out of the Sapling pool.
    fn value_balance(&self) -> &V;
    /// The authorizing data.
    fn authorization(&self) -> &A;
}

impl<A: Authorization> SpendDescriptionEncoding<A> for SpendDescription<A> {
    fn cv_bytes(&self) -> [u8; 32] {
        self.cv().to_bytes()
    }
    fn anchor(&self) -> &bls12_381::Scalar {
        SpendDescription::anchor(self)
    }
    fn nullifier(&self) -> &Nullifier {
        SpendDescription::nullifier(self)
    }
    fn rk_bytes(&self) -> [u8; 32] {
        (*self.rk()).into()
    }
    fn zkproof(&self) -> &A::SpendProof {
        SpendDescription::zkproof(self)
    }
    fn spend_auth_sig(&self) -> &A::AuthSig {
        SpendDescription::spend_auth_sig(self)
    }
}

impl<A: Authorization> SpendDescriptionEncoding<A> for SpendDescriptionBytes<A> {
    fn cv_bytes(&self) -> [u8; 32] {
        self.cv().to_bytes()
    }
    fn anchor(&self) -> &bls12_381::Scalar {
        SpendDescriptionBytes::anchor(self)
    }
    fn nullifier(&self) -> &Nullifier {
        SpendDescriptionBytes::nullifier(self)
    }
    fn rk_bytes(&self) -> [u8; 32] {
        <[u8; 32]>::from(*self.rk())
    }
    fn zkproof(&self) -> &A::SpendProof {
        SpendDescriptionBytes::zkproof(self)
    }
    fn spend_auth_sig(&self) -> &A::AuthSig {
        SpendDescriptionBytes::spend_auth_sig(self)
    }
}

impl<Proof> OutputDescriptionEncoding<Proof> for OutputDescription<Proof> {
    fn cv_bytes(&self) -> [u8; 32] {
        self.cv().to_bytes()
    }
    fn cmu(&self) -> &ExtractedNoteCommitment {
        OutputDescription::cmu(self)
    }
    fn ephemeral_key(&self) -> &EphemeralKeyBytes {
        OutputDescription::ephemeral_key(self)
    }
    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        OutputDescription::enc_ciphertext(self)
    }
    fn out_ciphertext(&self) -> &[u8; OUT_CIPHERTEXT_SIZE] {
        OutputDescription::out_ciphertext(self)
    }
    fn zkproof(&self) -> &Proof {
        OutputDescription::zkproof(self)
    }
}

impl<Proof> OutputDescriptionEncoding<Proof> for OutputDescriptionBytes<Proof> {
    fn cv_bytes(&self) -> [u8; 32] {
        self.cv().to_bytes()
    }
    fn cmu(&self) -> &ExtractedNoteCommitment {
        OutputDescriptionBytes::cmu(self)
    }
    fn ephemeral_key(&self) -> &EphemeralKeyBytes {
        OutputDescriptionBytes::ephemeral_key(self)
    }
    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        OutputDescriptionBytes::enc_ciphertext(self)
    }
    fn out_ciphertext(&self) -> &[u8; OUT_CIPHERTEXT_SIZE] {
        OutputDescriptionBytes::out_ciphertext(self)
    }
    fn zkproof(&self) -> &Proof {
        OutputDescriptionBytes::zkproof(self)
    }
}

impl<A: Authorization, V> BundleEncoding<A, V> for Bundle<A, V> {
    type Spend = SpendDescription<A>;
    type Output = OutputDescription<A::OutputProof>;

    fn shielded_spends(&self) -> &[Self::Spend] {
        Bundle::shielded_spends(self)
    }
    fn shielded_outputs(&self) -> &[Self::Output] {
        Bundle::shielded_outputs(self)
    }
    fn value_balance(&self) -> &V {
        Bundle::value_balance(self)
    }
    fn authorization(&self) -> &A {
        Bundle::authorization(self)
    }
}

impl<A: Authorization, V> BundleEncoding<A, V> for BundleBytes<A, V> {
    type Spend = SpendDescriptionBytes<A>;
    type Output = OutputDescriptionBytes<A::OutputProof>;

    fn shielded_spends(&self) -> &[Self::Spend] {
        BundleBytes::shielded_spends(self)
    }
    fn shielded_outputs(&self) -> &[Self::Output] {
        BundleBytes::shielded_outputs(self)
    }
    fn value_balance(&self) -> &V {
        BundleBytes::value_balance(self)
    }
    fn authorization(&self) -> &A {
        BundleBytes::authorization(self)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{BundleEncoding, OutputDescriptionEncoding, SpendDescriptionEncoding};
    use crate::bundle::testing::arb_bundle;

    proptest! {
        #[test]
        fn both_tiers_expose_identical_encodings(bundle in arb_bundle(0i64)) {
            let Some(bundle) = bundle else { return Ok(()) };
            let bytes = bundle.clone().compress();

            prop_assert_eq!(bytes.shielded_spends().len(), bundle.shielded_spends().len());
            for (b, p) in BundleEncoding::shielded_spends(&bytes)
                .iter()
                .zip(BundleEncoding::shielded_spends(&bundle))
            {
                prop_assert_eq!(b.cv_bytes(), p.cv_bytes());
                prop_assert_eq!(b.anchor(), SpendDescriptionEncoding::anchor(p));
                prop_assert_eq!(b.nullifier(), SpendDescriptionEncoding::nullifier(p));
                prop_assert_eq!(b.rk_bytes(), p.rk_bytes());
                prop_assert_eq!(b.zkproof(), SpendDescriptionEncoding::zkproof(p));
                prop_assert_eq!(
                    <[u8; 64]>::from(*SpendDescriptionEncoding::spend_auth_sig(b)),
                    <[u8; 64]>::from(*SpendDescriptionEncoding::spend_auth_sig(p))
                );
            }

            prop_assert_eq!(bytes.shielded_outputs().len(), bundle.shielded_outputs().len());
            for (b, p) in BundleEncoding::shielded_outputs(&bytes)
                .iter()
                .zip(BundleEncoding::shielded_outputs(&bundle))
            {
                prop_assert_eq!(b.cv_bytes(), p.cv_bytes());
                prop_assert_eq!(
                    OutputDescriptionEncoding::cmu(b).to_bytes(),
                    OutputDescriptionEncoding::cmu(p).to_bytes()
                );
                prop_assert_eq!(
                    OutputDescriptionEncoding::ephemeral_key(b).0,
                    OutputDescriptionEncoding::ephemeral_key(p).0
                );
                prop_assert_eq!(
                    OutputDescriptionEncoding::enc_ciphertext(b),
                    OutputDescriptionEncoding::enc_ciphertext(p)
                );
                prop_assert_eq!(
                    OutputDescriptionEncoding::out_ciphertext(b),
                    OutputDescriptionEncoding::out_ciphertext(p)
                );
                prop_assert_eq!(
                    OutputDescriptionEncoding::zkproof(b),
                    OutputDescriptionEncoding::zkproof(p)
                );
            }

            prop_assert_eq!(BundleEncoding::value_balance(&bytes), BundleEncoding::value_balance(&bundle));
        }
    }
}
