use rand::{CryptoRng, RngCore};

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
        self.to_tx_data(|_| Ok(()), |_| Ok(()), |_| Ok(()), |_| Ok(EffectsOnly))
    }

    /// Extracts a fully authorized [regular `Bundle`] from this PCZT bundle.
    ///
    /// This is used by the Transaction Extractor role to produce the final transaction.
    ///
    /// [regular `Bundle`]: crate::Bundle
    pub fn extract<V: TryFrom<i64>>(
        self,
    ) -> Result<Option<crate::Bundle<Unbound, V>>, TxExtractorError> {
        self.to_tx_data(
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
                        .ok_or(TxExtractorError::MissingBindingSignatureSigningKey)?,
                })
            },
        )
    }

    fn to_tx_data<A, V, E, F, G, H, I>(
        &self,
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
                    self.anchor.inner(),
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

/// Authorizing data for a bundle of actions that is just missing a binding signature.
#[derive(Debug)]
pub struct Unbound {
    bsk: redjubjub::SigningKey<redjubjub::Binding>,
}

impl Authorization for Unbound {
    type SpendProof = GrothProofBytes;
    type OutputProof = GrothProofBytes;
    type AuthSig = redjubjub::Signature<redjubjub::SpendAuth>;
}

impl<V> crate::Bundle<Unbound, V> {
    /// Verifies the given sighash with every `spend_auth_sig`, and then binds the bundle.
    ///
    /// Returns `None` if the given sighash does not validate against every `spend_auth_sig`.
    pub fn apply_binding_signature<R: RngCore + CryptoRng>(
        self,
        sighash: [u8; 32],
        rng: R,
    ) -> Option<crate::Bundle<Authorized, V>> {
        if self
            .shielded_spends()
            .iter()
            .all(|spend| spend.rk().verify(&sighash, spend.spend_auth_sig()).is_ok())
        {
            Some(self.map_authorization(
                &mut (),
                |_, p| p,
                |_, p| p,
                |_, s| s,
                |_, Unbound { bsk }| Authorized {
                    binding_sig: bsk.sign(rng, &sighash),
                },
            ))
        } else {
            None
        }
    }
}
