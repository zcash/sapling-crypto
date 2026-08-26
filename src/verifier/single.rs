use bellman::groth16::verify_proof;
use redjubjub::{Binding, SpendAuth};
use zcash_note_encryption::EphemeralKeyBytes;

use super::SaplingVerificationContextInner;
use crate::{
    bundle::GrothProofBytes,
    circuit::{PreparedOutputVerifyingKey, PreparedSpendVerifyingKey},
    note::ExtractedNoteCommitment,
    value::ValueCommitmentBytes,
};

/// A context object for verifying the Sapling components of a single Zcash transaction.
pub struct SaplingVerificationContext {
    inner: SaplingVerificationContextInner,
}

impl SaplingVerificationContext {
    /// Construct a new context to be used with a single transaction.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        SaplingVerificationContext {
            inner: SaplingVerificationContextInner::new(),
        }
    }

    /// Perform consensus checks on a Sapling SpendDescription, while
    /// accumulating its value commitment inside the context for later use.
    #[allow(clippy::too_many_arguments)]
    pub fn check_spend(
        &mut self,
        cv: &ValueCommitmentBytes,
        anchor: bls12_381::Scalar,
        nullifier: &[u8; 32],
        rk: &redjubjub::VerificationKeyBytes<SpendAuth>,
        sighash_value: &[u8; 32],
        spend_auth_sig: redjubjub::Signature<SpendAuth>,
        zkproof: &GrothProofBytes,
        verifying_key: &PreparedSpendVerifyingKey,
    ) -> bool {
        self.inner.check_spend(
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            &mut (),
            // Infallible: check_spend decompressed these bytes (jubjub affine & extended
            // from_bytes share one acceptance set)
            |_, rk| {
                redjubjub::VerificationKey::try_from(*rk)
                    .expect("rk was validated by check_spend")
                    .verify(sighash_value, &spend_auth_sig)
                    .is_ok()
            },
            |_, proof, public_inputs| {
                verify_proof(&verifying_key.0, &proof, &public_inputs[..]).is_ok()
            },
        )
    }

    /// Perform consensus checks on a Sapling OutputDescription, while
    /// accumulating its value commitment inside the context for later use.
    pub fn check_output(
        &mut self,
        cv: &ValueCommitmentBytes,
        cmu: ExtractedNoteCommitment,
        epk: &EphemeralKeyBytes,
        zkproof: &GrothProofBytes,
        verifying_key: &PreparedOutputVerifyingKey,
    ) -> bool {
        self.inner
            .check_output(cv, cmu, epk, zkproof, |proof, public_inputs| {
                verify_proof(&verifying_key.0, &proof, &public_inputs[..]).is_ok()
            })
    }

    /// Perform consensus checks on the valueBalance and bindingSig parts of a
    /// Sapling transaction. All SpendDescriptions and OutputDescriptions must
    /// have been checked before calling this function.
    pub fn final_check<V: Into<i64>>(
        &self,
        value_balance: V,
        sighash_value: &[u8; 32],
        binding_sig: redjubjub::Signature<Binding>,
    ) -> bool {
        self.inner.final_check(value_balance, |bvk| {
            bvk.verify(sighash_value, &binding_sig).is_ok()
        })
    }
}
