use core::fmt;

use alloc::vec::Vec;
use rand::{CryptoRng, Rng};

use crate::value::{CommitmentSum, TrapdoorSum};

use super::SignerError;

impl super::Bundle {
    /// Finalizes the IO for this bundle.
    ///
    /// This uses the same sighash for every dummy spend, matching the legacy behavior in
    /// which the binding signature also uses that sighash. Prefer
    /// [`Bundle::finalize_io_with_sighashes`](super::Bundle::finalize_io_with_sighashes)
    /// when the bundle uses a distinct sighash per spend, as for v7 transactions.
    pub fn finalize_io<R: Rng + CryptoRng>(
        &mut self,
        sighash: [u8; 32],
        rng: R,
    ) -> Result<(), IoFinalizerError> {
        let spend_sighashes = vec![sighash; self.spends.len()];
        self.finalize_io_with_sighashes(&spend_sighashes, rng)
    }

    /// Finalizes the IO for this bundle, using a distinct sighash per spend.
    ///
    /// `spend_sighashes` must contain one sighash per spend, ordered by the spends'
    /// positions in this bundle. Each dummy spend is signed over the sighash at its own
    /// position.
    ///
    /// Returns [`IoFinalizerError::MismatchedSighashCount`] if `spend_sighashes` does not
    /// contain exactly one entry per spend. This is checked before the bundle is
    /// modified.
    pub fn finalize_io_with_sighashes<R: Rng + CryptoRng>(
        &mut self,
        spend_sighashes: &[[u8; 32]],
        mut rng: R,
    ) -> Result<(), IoFinalizerError> {
        let expected = self.spends.len();
        if spend_sighashes.len() != expected {
            return Err(IoFinalizerError::MismatchedSighashCount {
                expected,
                actual: spend_sighashes.len(),
            });
        }
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
        for (spend, sighash) in self.spends.iter_mut().zip(spend_sighashes) {
            // The `Option::take` ensures we don't have any spend authorizing keys in the
            // PCZT after the IO Finalizer has run.
            if let Some(ask) = spend.dummy_ask.take() {
                spend
                    .sign(*sighash, &ask, &mut rng)
                    .map_err(IoFinalizerError::DummySignature)?;
            }
        }

        Ok(())
    }
}

/// Errors that can occur while finalizing the I/O for a PCZT bundle.
#[derive(Debug)]
#[non_exhaustive]
pub enum IoFinalizerError {
    /// An error occurred while signing a dummy spend.
    DummySignature(SignerError),
    /// The `value_sum` field is too large for a `valueBalance`.
    InvalidValueSum,
    /// The number of per-spend sighashes did not match the number of spends in the
    /// bundle.
    MismatchedSighashCount {
        /// The number of spends in the bundle.
        expected: usize,
        /// The number of per-spend sighashes provided.
        actual: usize,
    },
    /// The IO Finalizer role requires all `rcv` fields to be set.
    MissingValueCommitTrapdoor,
    /// The `cv`, `rcv`, and `value_sum` values within the Sapling bundle are
    /// inconsistent.
    ValueCommitMismatch,
}

impl fmt::Display for IoFinalizerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IoFinalizerError::DummySignature(e) => {
                write!(f, "an error occurred while signing a dummy spend: {e}")
            }
            IoFinalizerError::InvalidValueSum => {
                write!(f, "the `value_sum` field is too large for a `valueBalance`")
            }
            IoFinalizerError::MismatchedSighashCount { expected, actual } => write!(
                f,
                "expected {expected} per-spend sighashes, but {actual} were provided"
            ),
            IoFinalizerError::MissingValueCommitTrapdoor => write!(
                f,
                "the IO Finalizer role requires all `rcv` fields to be set"
            ),
            IoFinalizerError::ValueCommitMismatch => write!(
                f,
                "`cv`, `rcv`, and `value_sum` within the Sapling bundle are inconsistent"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IoFinalizerError {}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use crate::pczt::testing::pczt_bundle;

    use super::IoFinalizerError;

    #[test]
    fn signs_each_spend_with_its_own_sighash() {
        let mut rng = StdRng::seed_from_u64(1);
        let (mut bundle, _) = pczt_bundle();
        let spend_sighashes = [[1; 32], [2; 32]];

        bundle
            .finalize_io_with_sighashes(&spend_sighashes, &mut rng)
            .unwrap();

        assert!(bundle.bsk.is_some());
        for (i, spend) in bundle.spends.iter().enumerate() {
            let sig = spend.spend_auth_sig.unwrap();
            assert!(spend.rk.verify(&spend_sighashes[i], &sig).is_ok());
            assert!(spend.rk.verify(&spend_sighashes[1 - i], &sig).is_err());
            assert!(spend.dummy_ask.is_none());
        }
    }

    #[test]
    fn rejects_mismatched_sighash_count_before_mutating() {
        let mut rng = StdRng::seed_from_u64(2);
        let (mut bundle, _) = pczt_bundle();

        assert!(matches!(
            bundle.finalize_io_with_sighashes(&[[0; 32]], &mut rng),
            Err(IoFinalizerError::MismatchedSighashCount {
                expected: 2,
                actual: 1,
            })
        ));
        assert!(bundle.bsk.is_none());
        assert!(bundle
            .spends
            .iter()
            .all(|spend| spend.spend_auth_sig.is_none()));
    }

    #[test]
    fn shared_sighash_wrapper_signs_with_the_shared_digest() {
        let mut rng = StdRng::seed_from_u64(3);
        let (mut bundle, _) = pczt_bundle();
        let sighash = [4; 32];

        bundle.finalize_io(sighash, &mut rng).unwrap();

        for spend in &bundle.spends {
            assert!(spend
                .rk
                .verify(&sighash, &spend.spend_auth_sig.unwrap())
                .is_ok());
        }
    }
}
