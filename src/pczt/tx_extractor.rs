use core::fmt;

use rand::{CryptoRng, Rng};

use crate::{
    bundle::{
        Authorization, Authorized, EffectsOnly, GrothProofBytes, OutputDescription,
        SpendDescription,
    },
    Bundle,
};

use super::{Output, Spend};

impl super::Bundle {
    /// Extracts the effects of this PCZT bundle as a [regular `Bundle`].
    ///
    /// This is used by the Signer role to produce the transaction sighash.
    ///
    /// [regular `Bundle`]: crate::Bundle
    pub fn extract_effects<V: TryFrom<i64>>(
        &self,
    ) -> Result<Option<crate::Bundle<EffectsOnly, V>>, TxExtractorError> {
        self.to_tx_data(
            Some,
            |_| Ok(()),
            |_| Ok(()),
            |_| Ok(()),
            |_| Ok(EffectsOnly),
        )
    }

    /// Extracts a fully authorized [regular `Bundle`] from this PCZT bundle.
    ///
    /// This is used by the Transaction Extractor role to produce the final transaction.
    ///
    /// [regular `Bundle`]: crate::Bundle
    pub fn extract<V: TryFrom<i64>>(
        &self,
    ) -> Result<Option<crate::Bundle<Unbound, V>>, TxExtractorError> {
        self.to_tx_data(
            |anchor| anchor,
            |spend| spend.zkproof.ok_or(TxExtractorError::MissingProof),
            |spend| {
                spend
                    .spend_auth_sig
                    .ok_or(TxExtractorError::MissingSpendAuthSig)
            },
            |output| output.zkproof.ok_or(TxExtractorError::MissingProof),
            |bundle| {
                Ok(Unbound {
                    bsk: bundle
                        .bsk
                        .clone()
                        .ok_or(TxExtractorError::MissingBindingSignatureSigningKey)?,
                })
            },
        )
    }

    fn to_tx_data<A, V, E, F, G, H, I>(
        &self,
        anchor: impl Fn(bls12_381::Scalar) -> A::Anchor,
        spend_proof: F,
        spend_auth: G,
        output_proof: H,
        bundle_auth: I,
    ) -> Result<Option<crate::Bundle<A, V>>, E>
    where
        A: Authorization,
        E: From<TxExtractorError>,
        F: Fn(&Spend) -> Result<<A as Authorization>::SpendProof, E>,
        G: Fn(&Spend) -> Result<<A as Authorization>::AuthSig, E>,
        H: Fn(&Output) -> Result<<A as Authorization>::OutputProof, E>,
        I: FnOnce(&Self) -> Result<A, E>,
        V: TryFrom<i64>,
    {
        let spends = self
            .spends
            .iter()
            .map(|spend| {
                Ok(SpendDescription::from_parts(
                    spend.cv.clone(),
                    anchor(self.anchor.inner()),
                    spend.nullifier,
                    spend.rk,
                    spend_proof(spend)?,
                    spend_auth(spend)?,
                ))
            })
            .collect::<Result<_, E>>()?;

        let outputs = self
            .outputs
            .iter()
            .map(|output| {
                Ok(OutputDescription::from_parts(
                    output.cv.clone(),
                    output.cmu,
                    output.ephemeral_key.clone(),
                    output.enc_ciphertext,
                    output.out_ciphertext,
                    output_proof(output)?,
                ))
            })
            .collect::<Result<_, E>>()?;

        let value_balance = i64::try_from(self.value_sum)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(TxExtractorError::ValueSumOutOfRange)?;

        let authorization = bundle_auth(self)?;

        Ok(Bundle::from_parts(
            spends,
            outputs,
            value_balance,
            authorization,
        ))
    }
}

/// Errors that can occur while extracting a regular Sapling bundle from a PCZT bundle.
#[derive(Debug)]
#[non_exhaustive]
pub enum TxExtractorError {
    /// The Transaction Extractor role requires `bsk` to be set.
    MissingBindingSignatureSigningKey,
    /// The Transaction Extractor role requires all `zkproof` fields to be set.
    MissingProof,
    /// The Transaction Extractor role requires all `spend_auth_sig` fields to be set.
    MissingSpendAuthSig,
    /// The value sum does not fit into a `valueBalance`.
    ValueSumOutOfRange,
}

impl fmt::Display for TxExtractorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TxExtractorError::MissingBindingSignatureSigningKey => {
                write!(f, "`bsk` must be set for the Transaction Extractor role")
            }
            TxExtractorError::MissingProof => write!(
                f,
                "`zkproof` fields must all be set for the Transaction Extractor role"
            ),
            TxExtractorError::MissingSpendAuthSig => write!(
                f,
                "`spend_auth_sig` fields must all be set for the Transaction Extractor role"
            ),
            TxExtractorError::ValueSumOutOfRange => {
                write!(f, "value sum does not fit into a `valueBalance`")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxExtractorError {}

/// Authorizing data for a bundle of actions that is just missing a binding signature.
#[derive(Debug)]
pub struct Unbound {
    bsk: redjubjub::SigningKey<redjubjub::Binding>,
}

impl Authorization for Unbound {
    type Anchor = bls12_381::Scalar;
    type SpendProof = GrothProofBytes;
    type OutputProof = GrothProofBytes;
    type AuthSig = redjubjub::Signature<redjubjub::SpendAuth>;
}

impl<V> crate::Bundle<Unbound, V> {
    /// Verifies the given sighash with every `spend_auth_sig`, and then binds the bundle.
    ///
    /// This uses the same sighash for every spend and for the binding signature. Prefer
    /// [`Bundle::apply_binding_signature_with_sighashes`] when the bundle uses a distinct
    /// sighash per spend, as for v7 transactions.
    ///
    /// Returns `None` if the given sighash does not validate against every `spend_auth_sig`.
    pub fn apply_binding_signature<R: Rng + CryptoRng>(
        self,
        sighash: [u8; 32],
        rng: R,
    ) -> Option<crate::Bundle<Authorized, V>> {
        let spend_sighashes = vec![sighash; self.shielded_spends().len()];
        self.apply_binding_signature_with_sighashes(&spend_sighashes, sighash, rng)
    }

    /// Verifies each `spend_auth_sig` against its own sighash, and then binds the bundle.
    ///
    /// `spend_sighashes` must contain one sighash per spend, ordered by the spends'
    /// positions in the bundle. The binding signature is created over `binding_sighash`.
    ///
    /// Returns `None` without binding the bundle if `spend_sighashes` does not contain
    /// exactly one entry per spend, or if any sighash does not validate against its
    /// spend's `spend_auth_sig`.
    pub fn apply_binding_signature_with_sighashes<R: Rng + CryptoRng>(
        self,
        spend_sighashes: &[[u8; 32]],
        binding_sighash: [u8; 32],
        rng: R,
    ) -> Option<crate::Bundle<Authorized, V>> {
        if spend_sighashes.len() != self.shielded_spends().len() {
            return None;
        }

        if self
            .shielded_spends()
            .iter()
            .zip(spend_sighashes)
            .all(|(spend, sighash)| spend.rk().verify(sighash, spend.spend_auth_sig()).is_ok())
        {
            Some(self.map_authorization(
                &mut (),
                |_, p| p,
                |_, p| p,
                |_, s| s,
                |_, Unbound { bsk }| Authorized {
                    binding_sig: bsk.sign(rng, &binding_sighash),
                },
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        bundle::{Authorized, Bundle},
        constants::GROTH_PROOF_SIZE,
        pczt::testing::pczt_bundle,
    };

    fn binding_verification_key(
        bundle: &Bundle<Authorized, i64>,
    ) -> redjubjub::VerificationKey<redjubjub::Binding> {
        crate::bundle::binding_verification_key(bundle)
    }

    #[test]
    fn binds_each_spend_and_binding_with_their_own_sighash() {
        let mut rng = StdRng::seed_from_u64(1);
        let spend_sighashes = [[1; 32], [2; 32]];
        let binding_sighash = [3; 32];

        // Mismatched per-spend digests are rejected.  Build a fresh PCZT so the
        // assertion does not require cloning the secret-bearing Unbound.
        {
            let (mut bundle, _) = pczt_bundle();
            bundle
                .finalize_io_with_sighashes(&spend_sighashes, &mut rng)
                .unwrap();
            for spend in bundle.spends.iter_mut() {
                spend.zkproof = Some([0; GROTH_PROOF_SIZE]);
            }
            for output in bundle.outputs.iter_mut() {
                output.zkproof = Some([0; GROTH_PROOF_SIZE]);
            }
            assert!(bundle
                .extract::<i64>()
                .unwrap()
                .unwrap()
                .apply_binding_signature_with_sighashes(
                    &[spend_sighashes[1], spend_sighashes[0]],
                    binding_sighash,
                    &mut rng,
                )
                .is_none());
        }

        let (mut bundle, _) = pczt_bundle();
        bundle
            .finalize_io_with_sighashes(&spend_sighashes, &mut rng)
            .unwrap();
        for spend in bundle.spends.iter_mut() {
            spend.zkproof = Some([0; GROTH_PROOF_SIZE]);
        }
        for output in bundle.outputs.iter_mut() {
            output.zkproof = Some([0; GROTH_PROOF_SIZE]);
        }
        let unbound = bundle.extract::<i64>().unwrap().unwrap();

        let authorized = unbound
            .apply_binding_signature_with_sighashes(&spend_sighashes, binding_sighash, &mut rng)
            .unwrap();

        for (i, spend) in authorized.shielded_spends().iter().enumerate() {
            assert!(spend
                .rk()
                .verify(&spend_sighashes[i], spend.spend_auth_sig())
                .is_ok());
        }

        let bvk = binding_verification_key(&authorized);
        assert!(bvk
            .verify(&binding_sighash, &authorized.authorization().binding_sig)
            .is_ok());
    }

    #[test]
    fn shared_sighash_wrapper_uses_the_shared_digest() {
        let mut rng = StdRng::seed_from_u64(2);
        let (mut bundle, _) = pczt_bundle();
        let sighash = [4; 32];

        bundle.finalize_io(sighash, &mut rng).unwrap();
        for spend in bundle.spends.iter_mut() {
            spend.zkproof = Some([0; GROTH_PROOF_SIZE]);
        }
        for output in bundle.outputs.iter_mut() {
            output.zkproof = Some([0; GROTH_PROOF_SIZE]);
        }
        let unbound = bundle.extract::<i64>().unwrap().unwrap();

        let authorized = unbound.apply_binding_signature(sighash, &mut rng).unwrap();

        for spend in authorized.shielded_spends() {
            assert!(spend.rk().verify(&sighash, spend.spend_auth_sig()).is_ok());
        }

        let bvk = binding_verification_key(&authorized);
        assert!(bvk
            .verify(&sighash, &authorized.authorization().binding_sig)
            .is_ok());
    }

    #[test]
    fn apply_binding_signature_rejects_wrong_sighash_count() {
        let mut rng = StdRng::seed_from_u64(3);
        let spend_sighashes = [[1; 32], [2; 32]];
        let binding_sighash = [3; 32];

        // Too few: the guard prevents the zip from silently truncating.
        {
            let (mut bundle, _) = pczt_bundle();
            bundle
                .finalize_io_with_sighashes(&spend_sighashes, &mut rng)
                .unwrap();
            for spend in bundle.spends.iter_mut() {
                spend.zkproof = Some([0; GROTH_PROOF_SIZE]);
            }
            for output in bundle.outputs.iter_mut() {
                output.zkproof = Some([0; GROTH_PROOF_SIZE]);
            }
            assert!(bundle
                .extract::<i64>()
                .unwrap()
                .unwrap()
                .apply_binding_signature_with_sighashes(&[[1; 32]], binding_sighash, &mut rng)
                .is_none());
        }

        // Too many: the guard prevents an index-out-of-bounds or ignoring extras.
        {
            let (mut bundle, _) = pczt_bundle();
            bundle
                .finalize_io_with_sighashes(&spend_sighashes, &mut rng)
                .unwrap();
            for spend in bundle.spends.iter_mut() {
                spend.zkproof = Some([0; GROTH_PROOF_SIZE]);
            }
            for output in bundle.outputs.iter_mut() {
                output.zkproof = Some([0; GROTH_PROOF_SIZE]);
            }
            assert!(bundle
                .extract::<i64>()
                .unwrap()
                .unwrap()
                .apply_binding_signature_with_sighashes(
                    &[[1; 32], [2; 32], [3; 32]],
                    binding_sighash,
                    &mut rng,
                )
                .is_none());
        }
    }
}
