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

/// Parses large lists in parallel and small lists serially, stopping at the first failure.
#[cfg(feature = "multicore")]
fn read_proofs_in_parallel<T: Sync>(
    descriptions: &[T],
    proof_bytes: impl Fn(&T) -> &crate::bundle::GrothProofBytes + Sync,
) -> Option<Vec<groth16::Proof<Bls12>>> {
    if descriptions.len() >= 4 {
        descriptions
            .par_iter()
            .map(|description| groth16::Proof::read(&proof_bytes(description)[..]).ok())
            .collect()
    } else {
        descriptions
            .iter()
            .map(|description| groth16::Proof::read(&proof_bytes(description)[..]).ok())
            .collect()
    }
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

        // Deserialize the spend proofs, in spend order.
        #[cfg(feature = "multicore")]
        let spend_proofs =
            read_proofs_in_parallel(bundle.shielded_spends(), |spend| spend.zkproof());
        #[cfg(not(feature = "multicore"))]
        let spend_proofs = bundle
            .shielded_spends()
            .iter()
            .map(|spend| groth16::Proof::read(&spend.zkproof()[..]).ok())
            .collect::<Option<Vec<_>>>();
        let spend_proofs = match spend_proofs {
            Some(proofs) => proofs,
            None => return false,
        };

        for ((spend, sighash), zkproof) in bundle
            .shielded_spends()
            .iter()
            .zip(spend_sighashes)
            .zip(spend_proofs)
        {
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

        // Deserialize the ephemeral keys first, because doing so is much cheaper than
        // deserializing the output proofs.
        let epks = match bundle
            .shielded_outputs()
            .iter()
            .map(|output| jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key().0).into())
            .collect::<Option<Vec<jubjub::ExtendedPoint>>>()
        {
            Some(epks) => epks,
            None => return false,
        };

        // Deserialize the output proofs, in output order.
        #[cfg(feature = "multicore")]
        let output_proofs =
            read_proofs_in_parallel(bundle.shielded_outputs(), |output| output.zkproof());
        #[cfg(not(feature = "multicore"))]
        let output_proofs = bundle
            .shielded_outputs()
            .iter()
            .map(|output| groth16::Proof::read(&output.zkproof()[..]).ok())
            .collect::<Option<Vec<_>>>();
        let output_proofs = match output_proofs {
            Some(proofs) => proofs,
            None => return false,
        };

        for ((output, epk), zkproof) in bundle
            .shielded_outputs()
            .iter()
            .zip(epks)
            .zip(output_proofs)
        {
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
