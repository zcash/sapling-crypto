use bellman::{gadgets::multipack, groth16::Proof};
use bls12_381::Bls12;
use group::ff::PrimeField;
use redjubjub::{Binding, SpendAuth};
use zcash_note_encryption::EphemeralKeyBytes;

use crate::{
    bundle::GrothProofBytes,
    note::ExtractedNoteCommitment,
    primitives::decompress_not_small_order,
    value::{CommitmentSum, ValueCommitmentBytes},
};

mod single;
pub use single::SaplingVerificationContext;

mod batch;
pub use batch::BatchValidator;

/// A context object for verifying the Sapling components of a Zcash transaction.
struct SaplingVerificationContextInner {
    // (sum of the Spend value commitments) - (sum of the Output value commitments)
    cv_sum: CommitmentSum,
}

impl SaplingVerificationContextInner {
    /// Construct a new context to be used with a single transaction.
    fn new() -> Self {
        SaplingVerificationContextInner {
            cv_sum: CommitmentSum::zero(),
        }
    }

    /// Perform consensus checks on a Sapling SpendDescription, while
    /// accumulating its value commitment inside the context for later use.
    #[allow(clippy::too_many_arguments)]
    fn check_spend<C>(
        &mut self,
        cv: &ValueCommitmentBytes,
        anchor: bls12_381::Scalar,
        nullifier: &[u8; 32],
        rk: &redjubjub::VerificationKeyBytes<SpendAuth>,
        zkproof: &GrothProofBytes,
        verifier_ctx: &mut C,
        spend_auth_sig_verifier: impl FnOnce(
            &mut C,
            &redjubjub::VerificationKeyBytes<SpendAuth>,
        ) -> bool,
        proof_verifier: impl FnOnce(&mut C, Proof<Bls12>, [bls12_381::Scalar; 7]) -> bool,
    ) -> bool {
        // Proof encoding checked here too → no rule left to the caller
        let zkproof = match Proof::read(&zkproof[..]) {
            Ok(zkproof) => zkproof,
            Err(_) => return false,
        };

        // cv & rk rules enforced here, not at parse (both held compressed)
        // https://zips.z.cash/protocol/protocol.pdf#spenddesc
        let (cv, cv_coords) = match cv.decompress() {
            Ok(cv) => cv,
            Err(_) => return false,
        };

        let rk_affine = match decompress_not_small_order(&(*rk).into()) {
            Ok(rk_affine) => rk_affine,
            Err(_) => return false,
        };

        // Accumulate the value commitment in the context
        self.cv_sum += &cv;

        // Grab the nullifier as a sequence of bytes
        let nullifier = &nullifier[..];

        // Verify the spend_auth_sig
        if !spend_auth_sig_verifier(verifier_ctx, rk) {
            return false;
        }

        // Construct public input for circuit
        let mut public_input = [bls12_381::Scalar::zero(); 7];
        // Both already affine, from the square roots above (no curve arithmetic here)
        public_input[0] = rk_affine.get_u();
        public_input[1] = rk_affine.get_v();
        public_input[2] = cv_coords.u;
        public_input[3] = cv_coords.v;
        public_input[4] = anchor;

        // Add the nullifier through multiscalar packing
        {
            let nullifier = multipack::bytes_to_bits_le(nullifier);
            let nullifier = multipack::compute_multipacking(&nullifier);

            assert_eq!(nullifier.len(), 2);

            public_input[5] = nullifier[0];
            public_input[6] = nullifier[1];
        }

        // Verify the proof
        proof_verifier(verifier_ctx, zkproof, public_input)
    }

    /// Perform consensus checks on a Sapling OutputDescription, while
    /// accumulating its value commitment inside the context for later use.
    fn check_output(
        &mut self,
        cv: &ValueCommitmentBytes,
        cmu: ExtractedNoteCommitment,
        epk: &EphemeralKeyBytes,
        zkproof: &GrothProofBytes,
        proof_verifier: impl FnOnce(Proof<Bls12>, [bls12_381::Scalar; 5]) -> bool,
    ) -> bool {
        // Proof encoding checked here too → no rule left to the caller
        let zkproof = match Proof::read(&zkproof[..]) {
            Ok(zkproof) => zkproof,
            Err(_) => return false,
        };

        // cv & epk rules enforced here, not at parse (both held compressed)
        // https://zips.z.cash/protocol/protocol.pdf#outputdesc
        let (cv, cv_coords) = match cv.decompress() {
            Ok(cv) => cv,
            Err(_) => return false,
        };

        let epk_affine = match decompress_not_small_order(&epk.0) {
            Ok(epk_affine) => epk_affine,
            Err(_) => return false,
        };

        // Accumulate the value commitment in the context
        self.cv_sum -= &cv;

        // Construct public input for circuit
        let mut public_input = [bls12_381::Scalar::zero(); 5];
        // Both already affine, from the square roots above (no curve arithmetic here)
        public_input[0] = cv_coords.u;
        public_input[1] = cv_coords.v;
        public_input[2] = epk_affine.get_u();
        public_input[3] = epk_affine.get_v();
        public_input[4] = bls12_381::Scalar::from_repr(cmu.to_bytes()).unwrap();

        // Verify the proof
        proof_verifier(zkproof, public_input)
    }

    /// Perform consensus checks on the valueBalance and bindingSig parts of a
    /// Sapling transaction. All SpendDescriptions and OutputDescriptions must
    /// have been checked before calling this function.
    fn final_check<V: Into<i64>>(
        &self,
        value_balance: V,
        binding_sig_verifier: impl FnOnce(redjubjub::VerificationKey<Binding>) -> bool,
    ) -> bool {
        // Compute the final bvk.
        let bvk = self.cv_sum.into_bvk(value_balance);

        // Verify the binding_sig
        binding_sig_verifier(bvk)
    }
}

#[cfg(test)]
mod tests {
    use bellman::groth16::Proof;
    use bls12_381::Bls12;
    use group::{Group, GroupEncoding};
    use rand_core::OsRng;
    use redjubjub::{SigningKey, SpendAuth, VerificationKey, VerificationKeyBytes};

    use zcash_note_encryption::EphemeralKeyBytes;

    use super::{GrothProofBytes, SaplingVerificationContextInner};
    use crate::{
        note::ExtractedNoteCommitment,
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueCommitmentBytes},
    };

    // cv, rk & epk rules live in check_spend / check_output, not parse — pin each rejection

    // Well-formed, so the proof-encoding check (now first) is not what rejects these.
    // Proof stub returns true → a rejection that stopped running fails the test
    fn dummy_proof() -> GrothProofBytes {
        let mut bytes = [0u8; crate::constants::GROTH_PROOF_SIZE];
        Proof::<Bls12> {
            a: bls12_381::G1Affine::generator(),
            b: bls12_381::G2Affine::generator(),
            c: bls12_381::G1Affine::generator(),
        }
        .write(&mut bytes[..])
        .expect("a Groth16 proof serializes to GROTH_PROOF_SIZE bytes");
        bytes
    }

    // Canonical encoding of a small-order point (identity has order 1)
    fn small_order_encoding() -> [u8; 32] {
        jubjub::ExtendedPoint::identity().to_bytes()
    }

    // Not a canonical encoding of any Jubjub point
    const NON_CANONICAL: [u8; 32] = [0xff; 32];

    fn valid_cv() -> ValueCommitmentBytes {
        ValueCommitmentBytes::from(&ValueCommitment::derive(
            NoteValue::from_raw(42),
            ValueCommitTrapdoor::random(OsRng),
        ))
    }

    fn valid_rk() -> VerificationKeyBytes<SpendAuth> {
        VerificationKey::from(&SigningKey::<SpendAuth>::new(OsRng)).into()
    }

    fn check_spend_with(cv: ValueCommitmentBytes, rk: VerificationKeyBytes<SpendAuth>) -> bool {
        SaplingVerificationContextInner::new().check_spend(
            &cv,
            bls12_381::Scalar::zero(),
            &[0u8; 32],
            &rk,
            &dummy_proof(),
            &mut (),
            |_, _| true,
            |_, _, _| true,
        )
    }

    fn valid_epk() -> EphemeralKeyBytes {
        EphemeralKeyBytes(jubjub::ExtendedPoint::generator().to_bytes())
    }

    fn check_output_with(cv: ValueCommitmentBytes, epk: EphemeralKeyBytes) -> bool {
        SaplingVerificationContextInner::new().check_output(
            &cv,
            ExtractedNoteCommitment::from_bytes(&bls12_381::Scalar::zero().to_bytes()).unwrap(),
            &epk,
            &dummy_proof(),
            |_, _| true,
        )
    }

    #[test]
    fn check_spend_accepts_valid_cv_and_rk() {
        assert!(check_spend_with(valid_cv(), valid_rk()));
    }

    #[test]
    fn check_spend_rejects_small_order_cv() {
        assert!(!check_spend_with(
            ValueCommitmentBytes::from(small_order_encoding()),
            valid_rk(),
        ));
    }

    #[test]
    fn check_spend_rejects_non_canonical_cv() {
        assert!(!check_spend_with(
            ValueCommitmentBytes::from(NON_CANONICAL),
            valid_rk(),
        ));
    }

    #[test]
    fn check_spend_rejects_small_order_rk() {
        assert!(!check_spend_with(
            valid_cv(),
            VerificationKeyBytes::from(small_order_encoding()),
        ));
    }

    #[test]
    fn check_spend_rejects_non_canonical_rk() {
        assert!(!check_spend_with(
            valid_cv(),
            VerificationKeyBytes::from(NON_CANONICAL),
        ));
    }

    #[test]
    fn check_output_accepts_valid_cv_and_epk() {
        assert!(check_output_with(valid_cv(), valid_epk()));
    }

    #[test]
    fn check_output_rejects_small_order_cv() {
        assert!(!check_output_with(
            ValueCommitmentBytes::from(small_order_encoding()),
            valid_epk(),
        ));
    }

    #[test]
    fn check_output_rejects_non_canonical_cv() {
        assert!(!check_output_with(
            ValueCommitmentBytes::from(NON_CANONICAL),
            valid_epk(),
        ));
    }

    // Proof encoding moved in from the caller too
    #[test]
    fn check_spend_rejects_malformed_proof() {
        assert!(!SaplingVerificationContextInner::new().check_spend(
            &valid_cv(),
            bls12_381::Scalar::zero(),
            &[0u8; 32],
            &valid_rk(),
            &[0xff; crate::constants::GROTH_PROOF_SIZE],
            &mut (),
            |_, _| true,
            |_, _, _| true,
        ));
    }

    // epk rules moved in from the caller
    #[test]
    fn check_output_rejects_small_order_epk() {
        assert!(!check_output_with(
            valid_cv(),
            EphemeralKeyBytes(small_order_encoding()),
        ));
    }

    #[test]
    fn check_output_rejects_non_canonical_epk() {
        assert!(!check_output_with(
            valid_cv(),
            EphemeralKeyBytes(NON_CANONICAL),
        ));
    }
}
