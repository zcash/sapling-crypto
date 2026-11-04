#[cfg(feature = "multicore")]
use alloc::vec::Vec;
use bls12_381::Bls12;
use group::GroupEncoding;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "multicore")]
use rayon::prelude::*;

use super::SaplingVerificationContextInner;
use crate::{
    bundle::{Authorized, Bundle},
    circuit::{OutputVerifyingKey, SpendVerifyingKey},
};

#[cfg(test)]
mod tests;

/// Prepares only large lists; an empty iterator leaves small lists streaming.
#[cfg(feature = "multicore")]
fn read_proofs_in_parallel<T: Sync>(
    descriptions: &[T],
    proof_bytes: impl Fn(&T) -> &crate::bundle::GrothProofBytes + Sync,
) -> alloc::vec::IntoIter<Option<groth16::Proof<Bls12>>> {
    if descriptions.len() >= 4 {
        descriptions
            .par_iter()
            .map(|description| groth16::Proof::read(&proof_bytes(description)[..]).ok())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    }
    .into_iter()
}

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
    /// Returns `false` if the bundle doesn't satisfy all of the consensus rules. This
    /// `BatchValidator` can continue to be used regardless, but some or all of the proofs
    /// and signatures from this bundle may have already been added to the batch even if
    /// it fails other consensus rules.
    pub fn check_bundle<V: Copy + Into<i64>>(
        &mut self,
        bundle: Bundle<Authorized, V>,
        sighash: [u8; 32],
    ) -> bool {
        self.bundles_added = true;

        let mut ctx = SaplingVerificationContextInner::new();

        // Indexed parallel collection preserves each proof's association with its description.
        // Keep individual failures so earlier items are still queued before returning false.
        #[cfg(feature = "multicore")]
        let mut spend_proofs =
            read_proofs_in_parallel(bundle.shielded_spends(), |spend| spend.zkproof());

        for spend in bundle.shielded_spends() {
            // Deserialize the proof
            let read_proof = || groth16::Proof::read(&spend.zkproof()[..]).ok();
            #[cfg(feature = "multicore")]
            let zkproof = spend_proofs.next().unwrap_or_else(read_proof);
            #[cfg(not(feature = "multicore"))]
            let zkproof = read_proof();
            let zkproof = match zkproof {
                Some(p) => p,
                None => return false,
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
                        .queue(((*rk).into(), *spend.spend_auth_sig(), &sighash));
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

        // Do not parse outputs after an invalid spend, or retain both parsed lists at once.
        #[cfg(feature = "multicore")]
        drop(spend_proofs);
        #[cfg(feature = "multicore")]
        let mut output_proofs =
            read_proofs_in_parallel(bundle.shielded_outputs(), |output| output.zkproof());

        for output in bundle.shielded_outputs() {
            // Deserialize the ephemeral key
            let epk = match jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key().0).into() {
                Some(p) => p,
                None => return false,
            };

            // Deserialize the proof
            let read_proof = || groth16::Proof::read(&output.zkproof()[..]).ok();
            #[cfg(feature = "multicore")]
            let zkproof = output_proofs.next().unwrap_or_else(read_proof);
            #[cfg(not(feature = "multicore"))]
            let zkproof = read_proof();
            let zkproof = match zkproof {
                Some(p) => p,
                None => return false,
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
            self.signatures
                .queue((bvk.into(), bundle.authorization().binding_sig, &sighash));
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
