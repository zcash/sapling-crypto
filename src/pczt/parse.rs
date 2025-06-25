use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use ff::PrimeField;
use zcash_note_encryption::{EphemeralKeyBytes, OutgoingCipherKey};
use zip32::ChildIndex;

use super::{Bundle, Output, Spend, Zip32Derivation};
use crate::{
    bundle::GrothProofBytes,
    keys::{SpendAuthorizingKey, SpendValidatingKey},
    note::ExtractedNoteCommitment,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueSum},
    Anchor, MerklePath, Node, Nullifier, PaymentAddress, ProofGenerationKey, Rseed,
};

impl Bundle {
    /// Parses a PCZT bundle from its component parts.
    pub fn parse(
        spends: Vec<Spend>,
        outputs: Vec<Output>,
        value_sum: i128,
        anchor: [u8; 32],
        bsk: Option<[u8; 32]>,
    ) -> Result<Self, ParseError> {
        let value_sum = ValueSum::from_raw(value_sum);

        let anchor = Anchor::from_bytes(anchor)
            .into_option()
            .ok_or(ParseError::InvalidAnchor)?;

        let bsk = bsk
            .map(redjubjub::SigningKey::try_from)
            .transpose()
            .map_err(|_| ParseError::InvalidBindingSignatureSigningKey)?;

        Ok(Self {
            spends,
            outputs,
            value_sum,
            anchor,
            bsk,
        })
    }
}

impl Spend {
    /// Parses a PCZT spend from its component parts.
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        cv: [u8; 32],
        nullifier: [u8; 32],
        rk: [u8; 32],
        zkproof: Option<GrothProofBytes>,
        spend_auth_sig: Option<[u8; 64]>,
        recipient: Option<[u8; 43]>,
        value: Option<u64>,
        rcm: Option<[u8; 32]>,
        rseed: Option<[u8; 32]>,
        rcv: Option<[u8; 32]>,
        proof_generation_key: Option<([u8; 32], [u8; 32])>,
        witness: Option<(u32, [[u8; 32]; 32])>,
        alpha: Option<[u8; 32]>,
        zip32_derivation: Option<Zip32Derivation>,
        dummy_ask: Option<[u8; 32]>,
        proprietary: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, ParseError> {
        let cv = ValueCommitment::from_bytes_not_small_order(&cv)
            .into_option()
            .ok_or(ParseError::InvalidValueCommitment)?;

        let nullifier = Nullifier(nullifier);

        let rk = redjubjub::VerificationKey::try_from(rk)
            .map_err(|_| ParseError::InvalidRandomizedKey)?;

        let spend_auth_sig = spend_auth_sig.map(redjubjub::Signature::from);

        let recipient = recipient
            .as_ref()
            .map(|r| PaymentAddress::from_bytes(r).ok_or(ParseError::InvalidRecipient))
            .transpose()?;

        let value = value.map(NoteValue::from_raw);

        let rseed = match (rcm, rseed) {
            (None, None) => Ok(None),
            (Some(rcm), None) => jubjub::Scalar::from_repr(rcm)
                .into_option()
                .ok_or(ParseError::InvalidNoteCommitRandomness)
                .map(Rseed::BeforeZip212)
                .map(Some),
            (None, Some(rseed)) => Ok(Some(Rseed::AfterZip212(rseed))),
            (Some(_), Some(_)) => Err(ParseError::MixedNoteCommitRandomnessAndRseed),
        }?;

        let rcv = rcv
            .map(|rcv| {
                ValueCommitTrapdoor::from_bytes(rcv)
                    .into_option()
                    .ok_or(ParseError::InvalidValueCommitTrapdoor)
            })
            .transpose()?;

        let proof_generation_key = proof_generation_key
            .map(|(ak, nsk)| {
                Ok(ProofGenerationKey {
                    ak: SpendValidatingKey::from_bytes(&ak)
                        .ok_or(ParseError::InvalidProofGenerationKey)?,
                    nsk: jubjub::Scalar::from_repr(nsk)
                        .into_option()
                        .ok_or(ParseError::InvalidProofGenerationKey)?,
                })
            })
            .transpose()?;

        let witness = witness
            .map(|(position, auth_path_bytes)| {
                let path_elems = auth_path_bytes
                    .into_iter()
                    .map(|hash| {
                        Node::from_bytes(hash)
                            .into_option()
                            .ok_or(ParseError::InvalidWitness)
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                MerklePath::from_parts(path_elems, u64::from(position).into())
                    .map_err(|()| ParseError::InvalidWitness)
            })
            .transpose()?;

        let alpha = alpha
            .map(|alpha| {
                jubjub::Scalar::from_repr(alpha)
                    .into_option()
                    .ok_or(ParseError::InvalidSpendAuthRandomizer)
            })
            .transpose()?;

        let dummy_ask = dummy_ask
            .map(|dummy_ask| {
                SpendAuthorizingKey::from_bytes(&dummy_ask)
                    .ok_or(ParseError::InvalidDummySpendAuthorizingKey)
            })
            .transpose()?;

        Ok(Self {
            cv,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
            recipient,
            value,
            rseed,
            rcv,
            proof_generation_key,
            witness,
            alpha,
            zip32_derivation,
            dummy_ask,
            proprietary,
        })
    }
}

impl Output {
    /// Parses a PCZT output from its component parts.
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        cv: [u8; 32],
        cmu: [u8; 32],
        ephemeral_key: [u8; 32],
        enc_ciphertext: Vec<u8>,
        out_ciphertext: Vec<u8>,
        zkproof: Option<GrothProofBytes>,
        recipient: Option<[u8; 43]>,
        value: Option<u64>,
        rseed: Option<[u8; 32]>,
        rcv: Option<[u8; 32]>,
        ock: Option<[u8; 32]>,
        zip32_derivation: Option<Zip32Derivation>,
        user_address: Option<String>,
        proprietary: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, ParseError> {
        let cv = ValueCommitment::from_bytes_not_small_order(&cv)
            .into_option()
            .ok_or(ParseError::InvalidValueCommitment)?;

        let cmu = ExtractedNoteCommitment::from_bytes(&cmu)
            .into_option()
            .ok_or(ParseError::InvalidExtractedNoteCommitment)?;

        let ephemeral_key = EphemeralKeyBytes(ephemeral_key);

        let enc_ciphertext = enc_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| ParseError::InvalidEncCiphertext)?;

        let out_ciphertext = out_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| ParseError::InvalidOutCiphertext)?;

        let recipient = recipient
            .as_ref()
            .map(|r| PaymentAddress::from_bytes(r).ok_or(ParseError::InvalidRecipient))
            .transpose()?;

        let value = value.map(NoteValue::from_raw);

        let rcv = rcv
            .map(|rcv| {
                ValueCommitTrapdoor::from_bytes(rcv)
                    .into_option()
                    .ok_or(ParseError::InvalidValueCommitTrapdoor)
            })
            .transpose()?;

        let ock = ock.map(OutgoingCipherKey);

        Ok(Self {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
            recipient,
            value,
            rseed,
            rcv,
            ock,
            zip32_derivation,
            user_address,
            proprietary,
        })
    }
}

impl Zip32Derivation {
    /// Parses a ZIP 32 derivation path from its component parts.
    ///
    /// Returns an error if any of the derivation path indices are non-hardened (which
    /// this crate does not support, even though Sapling does).
    pub fn parse(
        seed_fingerprint: [u8; 32],
        derivation_path: Vec<u32>,
    ) -> Result<Self, ParseError> {
        Ok(Self {
            seed_fingerprint,
            derivation_path: derivation_path
                .into_iter()
                .map(|i| ChildIndex::from_index(i).ok_or(ParseError::InvalidZip32Derivation))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Errors that can occur while parsing a PCZT bundle.
#[derive(Debug)]
pub enum ParseError {
    /// An invalid `anchor` was provided.
    InvalidAnchor,
    /// An invalid `bsk` was provided.
    InvalidBindingSignatureSigningKey,
    /// An invalid `dummy_ask` was provided.
    InvalidDummySpendAuthorizingKey,
    /// An invalid `enc_ciphertext` was provided.
    InvalidEncCiphertext,
    /// An invalid `cmu` was provided.
    InvalidExtractedNoteCommitment,
    /// An invalid `rcm` was provided.
    InvalidNoteCommitRandomness,
    /// An invalid `out_ciphertext` was provided.
    InvalidOutCiphertext,
    /// An invalid `proof_generation_key` was provided.
    InvalidProofGenerationKey,
    /// An invalid `rk` was provided.
    InvalidRandomizedKey,
    /// An invalid `recipient` was provided.
    InvalidRecipient,
    /// An invalid `alpha` was provided.
    InvalidSpendAuthRandomizer,
    /// An invalid `cv` was provided.
    InvalidValueCommitment,
    /// An invalid `rcv` was provided.
    InvalidValueCommitTrapdoor,
    /// An invalid `witness` was provided.
    InvalidWitness,
    /// An invalid `zip32_derivation` was provided.
    InvalidZip32Derivation,
    /// Both `rcm` and `rseed` were provided for a Spend.
    MixedNoteCommitRandomnessAndRseed,
}
