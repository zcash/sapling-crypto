use bls12_381::Bls12;
use group::GroupEncoding;
use rand_core::{CryptoRng, Rng};

use super::SaplingVerificationContextInner;
use crate::{
    bundle::{Authorized, Bundle},
    circuit::{OutputVerifyingKey, SpendVerifyingKey},
};

/// Batch validation context for Sapling.
///
/// This batch-validates Spend and Output proofs, and RedJubjub signatures.
///
/// Signatures are verified assuming ZIP 216 is active.
pub struct BatchValidator {
    bundles_added: bool,
    spend_proofs: groth16::batch::Verifier<Bls12>,
    output_proofs: groth16::batch::Verifier<Bls12>,
    signatures: redjubjub::batch::Verifier,
}

impl Default for BatchValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchValidator {
    /// Constructs a new batch validation context.
    pub fn new() -> Self {
        BatchValidator {
            bundles_added: false,
            spend_proofs: groth16::batch::Verifier::new(),
            output_proofs: groth16::batch::Verifier::new(),
            signatures: redjubjub::batch::Verifier::new(),
        }
    }

    /// Checks the bundle against Sapling-specific consensus rules, and adds its proof and
    /// signatures to the validator.
    ///
    /// This uses the same sighash for every spend authorization signature and for the
    /// binding signature. Prefer [`BatchValidator::check_bundle_with_sighashes`] when the
    /// bundle uses a distinct sighash per spend, as for v7 transactions.
    ///
    /// Returns `false` if the bundle doesn't satisfy all of the consensus rules. This
    /// `BatchValidator` can continue to be used regardless, but some or all of the proofs
    /// and signatures from this bundle may have already been added to the batch even if
    /// it fails other consensus rules.
    pub fn check_bundle<V: Copy + Into<i64>>(
        &mut self,
        bundle: Bundle<Authorized, V>,
        sighash: [u8; 32],
    ) -> bool {
        let spend_sighashes = vec![sighash; bundle.shielded_spends().len()];
        self.check_bundle_with_sighashes(bundle, &spend_sighashes, sighash)
    }

    /// Checks the bundle against Sapling-specific consensus rules, and adds its proof and
    /// signatures to the validator.
    ///
    /// `spend_sighashes` must contain one sighash per spend, ordered by the spends'
    /// positions in the bundle. Each spend authorization signature is queued against the
    /// sighash at its own position, and the binding signature against `binding_sighash`.
    ///
    /// Returns `false` if `spend_sighashes` does not contain exactly one entry per spend,
    /// or if the bundle doesn't satisfy all of the consensus rules. This `BatchValidator`
    /// can continue to be used regardless, but some or all of the proofs and signatures
    /// from this bundle may have already been added to the batch even if it fails.
    pub fn check_bundle_with_sighashes<V: Copy + Into<i64>>(
        &mut self,
        bundle: Bundle<Authorized, V>,
        spend_sighashes: &[[u8; 32]],
        binding_sighash: [u8; 32],
    ) -> bool {
        if spend_sighashes.len() != bundle.shielded_spends().len() {
            return false;
        }

        self.bundles_added = true;

        let mut ctx = SaplingVerificationContextInner::new();

        for (spend, sighash) in bundle.shielded_spends().iter().zip(spend_sighashes) {
            // Deserialize the proof
            let zkproof = match groth16::Proof::read(&spend.zkproof()[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };

            // Check the Spend consensus rules, and batch its proof and spend
            // authorization signature.
            let consensus_rules_passed = ctx.check_spend(
                spend.cv(),
                *spend.anchor(),
                &spend.nullifier().0,
                spend.rk(),
                zkproof,
                self,
                |this, rk| {
                    this.signatures
                        .queue(((*rk).into(), *spend.spend_auth_sig(), sighash));
                    true
                },
                |this, proof, public_inputs| {
                    this.spend_proofs.queue((proof, public_inputs.to_vec()));
                    true
                },
            );
            if !consensus_rules_passed {
                return false;
            }
        }

        for output in bundle.shielded_outputs() {
            // Deserialize the ephemeral key
            let epk = match jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key().0).into() {
                Some(p) => p,
                None => return false,
            };

            // Deserialize the proof
            let zkproof = match groth16::Proof::read(&output.zkproof()[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };

            // Check the Output consensus rules, and batch its proof.
            let consensus_rules_passed = ctx.check_output(
                output.cv(),
                *output.cmu(),
                epk,
                zkproof,
                |proof, public_inputs| {
                    self.output_proofs.queue((proof, public_inputs.to_vec()));
                    true
                },
            );
            if !consensus_rules_passed {
                return false;
            }
        }

        // Check the whole-bundle consensus rules, and batch the binding signature.
        ctx.final_check(*bundle.value_balance(), |bvk| {
            self.signatures.queue((
                bvk.into(),
                bundle.authorization().binding_sig,
                &binding_sighash,
            ));
            true
        })
    }

    /// Batch-validates the accumulated bundles.
    ///
    /// Returns `true` if every proof and signature in every bundle added to the batch
    /// validator is valid, or `false` if one or more are invalid. No attempt is made to
    /// figure out which of the accumulated bundles might be invalid; if that information
    /// is desired, construct separate [`BatchValidator`]s for sub-batches of the bundles.
    pub fn validate<R: Rng + CryptoRng>(
        self,
        spend_vk: &SpendVerifyingKey,
        output_vk: &OutputVerifyingKey,
        mut rng: R,
    ) -> bool {
        if !self.bundles_added {
            // An empty batch is always valid, but is not free to run; skip it.
            return true;
        }

        if let Err(e) = self.signatures.verify(&mut rng) {
            #[cfg(feature = "std")]
            tracing::debug!("Signature batch validation failed: {}", e);
            #[cfg(not(feature = "std"))]
            tracing::debug!("Signature batch validation failed: {:?}", e);
            return false;
        }

        #[cfg(feature = "multicore")]
        let verify_proofs = |batch: groth16::batch::Verifier<Bls12>, vk| batch.verify_multicore(vk);

        #[cfg(not(feature = "multicore"))]
        let mut verify_proofs =
            |batch: groth16::batch::Verifier<Bls12>, vk| batch.verify(&mut rng, vk);

        if verify_proofs(self.spend_proofs, &spend_vk.0).is_err() {
            tracing::debug!("Spend proof batch validation failed");
            return false;
        }

        if verify_proofs(self.output_proofs, &output_vk.0).is_err() {
            tracing::debug!("Output proof batch validation failed");
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        builder::testing::proven_two_spend_bundle,
        bundle::{Authorized, Bundle, GrothProofBytes, OutputDescription, SpendDescription},
    };

    use super::BatchValidator;

    fn decodable_proof() -> GrothProofBytes {
        let proof = groth16::Proof::<bls12_381::Bls12> {
            a: bls12_381::G1Affine::generator(),
            b: bls12_381::G2Affine::generator(),
            c: bls12_381::G1Affine::generator(),
        };
        let mut bytes = Vec::new();
        proof.write(&mut bytes).unwrap();
        bytes.try_into().unwrap()
    }

    /// Replaces the mock proofs, which are all zeroes and thus do not decode, with
    /// encodable proofs. Signature batch validation does not use the proofs.
    fn with_decodable_proofs(bundle: Bundle<Authorized, i64>) -> Bundle<Authorized, i64> {
        let proof = decodable_proof();
        let spends = bundle
            .shielded_spends()
            .iter()
            .map(|spend| {
                SpendDescription::from_parts(
                    spend.cv().clone(),
                    *spend.anchor(),
                    *spend.nullifier(),
                    *spend.rk(),
                    proof,
                    *spend.spend_auth_sig(),
                )
            })
            .collect();
        let outputs = bundle
            .shielded_outputs()
            .iter()
            .map(|output| {
                OutputDescription::from_parts(
                    output.cv().clone(),
                    *output.cmu(),
                    output.ephemeral_key().clone(),
                    *output.enc_ciphertext(),
                    *output.out_ciphertext(),
                    proof,
                )
            })
            .collect();
        Bundle::from_parts(
            spends,
            outputs,
            *bundle.value_balance(),
            Authorized {
                binding_sig: bundle.authorization().binding_sig,
            },
        )
        .unwrap()
    }

    #[test]
    fn queues_each_spend_and_binding_under_their_own_sighash() {
        let mut rng = StdRng::seed_from_u64(1);
        let (bundle, ask) = proven_two_spend_bundle();
        let spend_sighashes = [[1; 32], [2; 32]];
        let binding_sighash = [3; 32];
        let bundle = with_decodable_proofs(
            bundle
                .apply_signatures_with_sighashes(
                    &mut rng,
                    &spend_sighashes,
                    binding_sighash,
                    core::slice::from_ref(&ask),
                )
                .unwrap(),
        );

        let mut validator = BatchValidator::new();
        assert!(validator.check_bundle_with_sighashes(
            bundle.clone(),
            &spend_sighashes,
            binding_sighash,
        ));
        assert!(validator.signatures.verify(&mut rng).is_ok());

        // The same signatures do not verify when the per-spend digests are not matched
        // to their spends.
        let mut validator = BatchValidator::new();
        assert!(validator.check_bundle_with_sighashes(
            bundle,
            &[spend_sighashes[1], spend_sighashes[0]],
            binding_sighash,
        ));
        assert!(validator.signatures.verify(&mut rng).is_err());
    }

    #[test]
    fn rejects_mismatched_sighash_count() {
        let mut rng = StdRng::seed_from_u64(2);
        let (bundle, ask) = proven_two_spend_bundle();
        let spend_sighashes = [[1; 32], [2; 32]];
        let binding_sighash = [3; 32];
        let authorized = with_decodable_proofs(
            bundle
                .apply_signatures_with_sighashes(
                    &mut rng,
                    &spend_sighashes,
                    binding_sighash,
                    core::slice::from_ref(&ask),
                )
                .unwrap(),
        );

        let mut validator = BatchValidator::new();
        assert!(!validator.check_bundle_with_sighashes(
            authorized.clone(),
            &spend_sighashes[..1],
            binding_sighash,
        ));

        let mut validator = BatchValidator::new();
        assert!(!validator.check_bundle_with_sighashes(
            authorized.clone(),
            &[spend_sighashes[0], spend_sighashes[1], [4; 32]],
            binding_sighash,
        ));

        let mut validator = BatchValidator::new();
        assert!(validator.check_bundle_with_sighashes(
            authorized,
            &spend_sighashes,
            binding_sighash,
        ));
        assert!(validator.signatures.verify(&mut rng).is_ok());
    }

    #[test]
    fn shared_sighash_wrapper_queues_the_shared_digest() {
        let mut rng = StdRng::seed_from_u64(3);
        let (bundle, ask) = proven_two_spend_bundle();
        let sighash = [4; 32];
        let bundle = with_decodable_proofs(
            bundle
                .apply_signatures(&mut rng, sighash, core::slice::from_ref(&ask))
                .unwrap(),
        );

        let mut validator = BatchValidator::new();
        assert!(validator.check_bundle(bundle, sighash));
        assert!(validator.signatures.verify(&mut rng).is_ok());
    }
}
