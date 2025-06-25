use alloc::vec::Vec;
use rand::{CryptoRng, RngCore};

use crate::value::{CommitmentSum, TrapdoorSum};

use super::SignerError;

impl super::Bundle {
    /// Finalizes the IO for this bundle.
    pub fn finalize_io<R: RngCore + CryptoRng>(
        &mut self,
        sighash: [u8; 32],
        mut rng: R,
    ) -> Result<(), IoFinalizerError> {
        // Compute the transaction binding signing key.
        let bsk = {
            let spend_rcvs = self
                .spends
                .iter()
                .map(|spend| {
                    spend
                        .rcv
                        .as_ref()
                        .ok_or(IoFinalizerError::MissingValueCommitTrapdoor)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let output_rcvs = self
                .outputs
                .iter()
                .map(|output| {
                    output
                        .rcv
                        .as_ref()
                        .ok_or(IoFinalizerError::MissingValueCommitTrapdoor)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let spends: TrapdoorSum = spend_rcvs.into_iter().sum();
            let outputs: TrapdoorSum = output_rcvs.into_iter().sum();
            (spends - outputs).into_bsk()
        };

        // Verify that bsk and bvk are consistent.
        let bvk = {
            let spends = self
                .spends
                .iter()
                .map(|spend| spend.cv())
                .sum::<CommitmentSum>();
            let outputs = self
                .outputs
                .iter()
                .map(|output| output.cv())
                .sum::<CommitmentSum>();
            (spends - outputs).into_bvk(
                i64::try_from(self.value_sum).map_err(|_| IoFinalizerError::InvalidValueSum)?,
            )
        };
        if redjubjub::VerificationKey::from(&bsk) != bvk {
            return Err(IoFinalizerError::ValueCommitMismatch);
        }
        self.bsk = Some(bsk);

        // Add signatures to dummy spends.
        for spend in self.spends.iter_mut() {
            // The `Option::take` ensures we don't have any spend authorizing keys in the
            // PCZT after the IO Finalizer has run.
            if let Some(ask) = spend.dummy_ask.take() {
                spend
                    .sign(sighash, &ask, &mut rng)
                    .map_err(IoFinalizerError::DummySignature)?;
            }
        }

        Ok(())
    }
}

/// Errors that can occur while finalizing the I/O for a PCZT bundle.
#[derive(Debug)]
pub enum IoFinalizerError {
    /// An error occurred while signing a dummy spend.
    DummySignature(SignerError),
    /// The `value_sum` is too large for the `value_balance` field.
    InvalidValueSum,
    /// The IO Finalizer role requires all `rcv` fields to be set.
    MissingValueCommitTrapdoor,
    /// The `cv_net`, `rcv`, and `value_sum` values within the Orchard bundle are
    /// inconsistent.
    ValueCommitMismatch,
}
