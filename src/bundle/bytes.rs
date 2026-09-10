//! Spend and Output descriptions with `cv` and `rk` left compressed.
//!
//! `epk` needs no tier of its own: a description already carries it as `EphemeralKeyBytes`.

use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

use memuse::DynamicUsage;
use redjubjub::{SpendAuth, VerificationKey, VerificationKeyBytes};
use zcash_note_encryption::{
    EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE,
};

use crate::{
    bundle::{
        Authorization, Authorized, Bundle, GrothProofBytes, OutputDescription, OutputDescriptionV5,
        SpendDescription, SpendDescriptionV5,
    },
    constants::GROTH_PROOF_SIZE,
    note::ExtractedNoteCommitment,
    note_encryption::{CompactOutputDescription, SaplingDomain},
    value::ValueCommitmentBytes,
    Nullifier,
};

/// `cv ‖ nullifier ‖ rk`, the fields a v5 transaction writes in the spend itself.
pub const SPEND_DESCRIPTION_V5_SIZE: usize = 96;

const SPEND_V5_CV: Range<usize> = 0..32;
const SPEND_V5_NULLIFIER: Range<usize> = 32..64;
const SPEND_V5_RK: Range<usize> = 64..SPEND_DESCRIPTION_V5_SIZE;

/// `cv ‖ anchor ‖ nullifier ‖ rk ‖ zkproof ‖ spendAuthSig`, per [Spend Description Encoding
/// and Consensus][spendenc].
///
/// [spendenc]: https://zips.z.cash/protocol/protocol.pdf#spendencodingandconsensus
pub const SPEND_DESCRIPTION_V4_SIZE: usize = 128 + GROTH_PROOF_SIZE + 64;

const SPEND_V4_CV: Range<usize> = 0..32;
const SPEND_V4_ANCHOR: Range<usize> = 32..64;
const SPEND_V4_NULLIFIER: Range<usize> = 64..96;
const SPEND_V4_RK: Range<usize> = 96..128;
const SPEND_V4_ZKPROOF: Range<usize> = 128..128 + GROTH_PROOF_SIZE;
const SPEND_V4_AUTH_SIG: Range<usize> = 128 + GROTH_PROOF_SIZE..SPEND_DESCRIPTION_V4_SIZE;

/// `cv ‖ cmu ‖ ephemeralKey ‖ encCiphertext ‖ outCiphertext`, the fields a v5 transaction
/// writes in the output itself.
pub const OUTPUT_DESCRIPTION_V5_SIZE: usize = 96 + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE;

const OUTPUT_V5_CV: Range<usize> = 0..32;
const OUTPUT_V5_CMU: Range<usize> = 32..64;
const OUTPUT_V5_EPK: Range<usize> = 64..96;
const OUTPUT_V5_ENC: Range<usize> = 96..96 + ENC_CIPHERTEXT_SIZE;
const OUTPUT_V5_OUT: Range<usize> = 96 + ENC_CIPHERTEXT_SIZE..OUTPUT_DESCRIPTION_V5_SIZE;

/// The v5 fields followed by `zkproof`, per [Output Description Encoding and
/// Consensus][outputenc].
///
/// [outputenc]: https://zips.z.cash/protocol/protocol.pdf#outputencodingandconsensus
pub const OUTPUT_DESCRIPTION_V4_SIZE: usize = OUTPUT_DESCRIPTION_V5_SIZE + GROTH_PROOF_SIZE;

const OUTPUT_V4_PREFIX: Range<usize> = 0..OUTPUT_DESCRIPTION_V5_SIZE;
const OUTPUT_V4_ZKPROOF: Range<usize> = OUTPUT_DESCRIPTION_V5_SIZE..OUTPUT_DESCRIPTION_V4_SIZE;

fn field(bytes: &[u8], range: Range<usize>) -> [u8; 32] {
    bytes[range]
        .try_into()
        .expect("every field range in this module is 32 bytes")
}

/// A [`SpendDescription`] with `cv` and `rk` left compressed.
#[derive(Clone)]
pub struct SpendDescriptionBytes<A: Authorization> {
    cv: ValueCommitmentBytes,
    anchor: bls12_381::Scalar,
    nullifier: Nullifier,
    rk: VerificationKeyBytes<SpendAuth>,
    zkproof: A::SpendProof,
    spend_auth_sig: A::AuthSig,
}

impl<A: Authorization> fmt::Debug for SpendDescriptionBytes<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SpendDescriptionBytes(cv = {:?}, anchor = {:?}, nullifier = {:?}, rk = {:?}, spend_auth_sig = {:?})",
            self.cv, self.anchor, self.nullifier, self.rk, self.spend_auth_sig
        )
    }
}

impl<A: Authorization> SpendDescriptionBytes<A> {
    pub fn cv(&self) -> &ValueCommitmentBytes {
        &self.cv
    }

    pub fn anchor(&self) -> &bls12_381::Scalar {
        &self.anchor
    }

    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }

    pub fn rk(&self) -> &VerificationKeyBytes<SpendAuth> {
        &self.rk
    }

    pub fn zkproof(&self) -> &A::SpendProof {
        &self.zkproof
    }

    pub fn spend_auth_sig(&self) -> &A::AuthSig {
        &self.spend_auth_sig
    }

    /// Drops the fields a v5 transaction writes in its own arrays. Inverse of
    /// [`SpendDescriptionV5Bytes::into_v4`].
    pub fn to_v5(&self) -> SpendDescriptionV5Bytes {
        SpendDescriptionV5Bytes {
            cv: self.cv,
            nullifier: self.nullifier,
            rk: self.rk,
        }
    }

    /// Recovers the [`SpendDescription`]. 2 sqrt.
    ///
    /// `rk`'s small-order rule stays with the spend verifier, as it is for a
    /// [`SpendDescription`] built any other way.
    pub fn decompress(self) -> Result<SpendDescription<A>, DecompressionError> {
        Ok(SpendDescription::from_parts(
            self.cv
                .decompress()
                .map_err(|_| DecompressionError::InvalidValueCommitment)?,
            self.anchor,
            self.nullifier,
            VerificationKey::try_from(self.rk)
                .map_err(|_| DecompressionError::NonCanonicalRandomizedKey)?,
            self.zkproof,
            self.spend_auth_sig,
        ))
    }
}

impl<A: Authorization> SpendDescription<A> {
    /// Drops to the encoded tier.
    ///
    /// Infallible: a description cannot hold a point that fails to encode.
    pub fn compress(self) -> SpendDescriptionBytes<A> {
        SpendDescriptionBytes {
            cv: ValueCommitmentBytes::from(&self.cv),
            anchor: self.anchor,
            nullifier: self.nullifier,
            rk: self.rk.into(),
            zkproof: self.zkproof,
            spend_auth_sig: self.spend_auth_sig,
        }
    }
}

impl SpendDescriptionBytes<Authorized> {
    /// Encodes this v4 Spend description.
    pub fn to_bytes(&self) -> [u8; SPEND_DESCRIPTION_V4_SIZE] {
        let mut bytes = [0u8; SPEND_DESCRIPTION_V4_SIZE];

        bytes[SPEND_V4_CV].copy_from_slice(&self.cv.to_bytes());
        bytes[SPEND_V4_ANCHOR].copy_from_slice(&self.anchor.to_bytes());
        bytes[SPEND_V4_NULLIFIER].copy_from_slice(&self.nullifier.0);
        bytes[SPEND_V4_RK].copy_from_slice(&<[u8; 32]>::from(self.rk));
        bytes[SPEND_V4_ZKPROOF].copy_from_slice(&self.zkproof);
        bytes[SPEND_V4_AUTH_SIG].copy_from_slice(&<[u8; 64]>::from(self.spend_auth_sig));

        bytes
    }

    /// Decodes a v4 Spend description, checking the `anchor` encoding. The point rules go to
    /// [`SpendDescriptionBytes::decompress`].
    pub fn from_bytes(
        bytes: &[u8; SPEND_DESCRIPTION_V4_SIZE],
    ) -> Result<Self, DescriptionParseError> {
        let anchor = Option::from(bls12_381::Scalar::from_bytes(&field(
            bytes,
            SPEND_V4_ANCHOR,
        )))
        .ok_or(DescriptionParseError::NonCanonicalAnchor)?;

        Ok(SpendDescriptionBytes {
            cv: ValueCommitmentBytes::from(field(bytes, SPEND_V4_CV)),
            anchor,
            nullifier: Nullifier(field(bytes, SPEND_V4_NULLIFIER)),
            rk: VerificationKeyBytes::from(field(bytes, SPEND_V4_RK)),
            zkproof: bytes[SPEND_V4_ZKPROOF]
                .try_into()
                .expect("the zkproof range is GROTH_PROOF_SIZE bytes"),
            spend_auth_sig: redjubjub::Signature::from(
                <[u8; 64]>::try_from(&bytes[SPEND_V4_AUTH_SIG])
                    .expect("the spendAuthSig range is 64 bytes"),
            ),
        })
    }
}

/// A [`SpendDescriptionV5`] with `cv` and `rk` left compressed.
#[derive(Clone, Debug)]
pub struct SpendDescriptionV5Bytes {
    cv: ValueCommitmentBytes,
    nullifier: Nullifier,
    rk: VerificationKeyBytes<SpendAuth>,
}

impl SpendDescriptionV5Bytes {
    pub fn cv(&self) -> &ValueCommitmentBytes {
        &self.cv
    }

    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }

    pub fn rk(&self) -> &VerificationKeyBytes<SpendAuth> {
        &self.rk
    }

    /// Pairs back on the fields a v5 transaction writes in its own arrays.
    ///
    /// Inverse of [`SpendDescriptionBytes::to_v5`].
    pub fn into_v4<A>(
        self,
        anchor: bls12_381::Scalar,
        zkproof: GrothProofBytes,
        spend_auth_sig: redjubjub::Signature<SpendAuth>,
    ) -> SpendDescriptionBytes<A>
    where
        A: Authorization<SpendProof = GrothProofBytes, AuthSig = redjubjub::Signature<SpendAuth>>,
    {
        SpendDescriptionBytes {
            cv: self.cv,
            anchor,
            nullifier: self.nullifier,
            rk: self.rk,
            zkproof,
            spend_auth_sig,
        }
    }

    /// Recovers the [`SpendDescriptionV5`]. 2 sqrt.
    pub fn decompress(self) -> Result<SpendDescriptionV5, DecompressionError> {
        Ok(SpendDescriptionV5::from_parts(
            self.cv
                .decompress()
                .map_err(|_| DecompressionError::InvalidValueCommitment)?,
            self.nullifier,
            VerificationKey::try_from(self.rk)
                .map_err(|_| DecompressionError::NonCanonicalRandomizedKey)?,
        ))
    }

    /// Encodes this v5 Spend description.
    pub fn to_bytes(&self) -> [u8; SPEND_DESCRIPTION_V5_SIZE] {
        let mut bytes = [0u8; SPEND_DESCRIPTION_V5_SIZE];

        bytes[SPEND_V5_CV].copy_from_slice(&self.cv.to_bytes());
        bytes[SPEND_V5_NULLIFIER].copy_from_slice(&self.nullifier.0);
        bytes[SPEND_V5_RK].copy_from_slice(&<[u8; 32]>::from(self.rk));

        bytes
    }

    /// Decodes a v5 Spend description. Infallible: every rule these three fields carry needs a
    /// point.
    pub fn from_bytes(bytes: &[u8; SPEND_DESCRIPTION_V5_SIZE]) -> Self {
        SpendDescriptionV5Bytes {
            cv: ValueCommitmentBytes::from(field(bytes, SPEND_V5_CV)),
            nullifier: Nullifier(field(bytes, SPEND_V5_NULLIFIER)),
            rk: VerificationKeyBytes::from(field(bytes, SPEND_V5_RK)),
        }
    }
}

impl SpendDescriptionV5 {
    /// Drops to the encoded tier.
    ///
    /// Infallible: a description cannot hold a point that fails to encode.
    pub fn compress(self) -> SpendDescriptionV5Bytes {
        SpendDescriptionV5Bytes {
            cv: ValueCommitmentBytes::from(&self.cv),
            nullifier: self.nullifier,
            rk: self.rk.into(),
        }
    }
}

/// An [`OutputDescription`] with `cv` left compressed.
///
/// `cmu` and `ephemeral_key` are already encodings on an [`OutputDescription`], so `cv` is the
/// whole of the difference between the two tiers.
#[derive(Clone)]
pub struct OutputDescriptionBytes<Proof> {
    cv: ValueCommitmentBytes,
    cmu: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    zkproof: Proof,
}

impl<Proof> fmt::Debug for OutputDescriptionBytes<Proof> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OutputDescriptionBytes(cv = {:?}, cmu = {:?}, ephemeral_key = {:?})",
            self.cv, self.cmu, self.ephemeral_key
        )
    }
}

impl<Proof> OutputDescriptionBytes<Proof> {
    pub fn cv(&self) -> &ValueCommitmentBytes {
        &self.cv
    }

    pub fn cmu(&self) -> &ExtractedNoteCommitment {
        &self.cmu
    }

    pub fn ephemeral_key(&self) -> &EphemeralKeyBytes {
        &self.ephemeral_key
    }

    pub fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }

    pub fn out_ciphertext(&self) -> &[u8; OUT_CIPHERTEXT_SIZE] {
        &self.out_ciphertext
    }

    pub fn zkproof(&self) -> &Proof {
        &self.zkproof
    }

    /// Drops the proof, which a v5 transaction writes in its own array. Inverse of
    /// [`OutputDescriptionV5Bytes::into_v4`].
    pub fn to_v5(&self) -> OutputDescriptionV5Bytes {
        OutputDescriptionV5Bytes {
            cv: self.cv,
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key.clone(),
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
        }
    }

    /// Recovers the [`OutputDescription`]. 1 sqrt.
    ///
    /// `epk`'s rules stay with the output verifier, as they are for an [`OutputDescription`]
    /// built any other way.
    pub fn decompress(self) -> Result<OutputDescription<Proof>, DecompressionError> {
        Ok(OutputDescription::from_parts(
            self.cv
                .decompress()
                .map_err(|_| DecompressionError::InvalidValueCommitment)?,
            self.cmu,
            self.ephemeral_key,
            self.enc_ciphertext,
            self.out_ciphertext,
            self.zkproof,
        ))
    }
}

impl<Proof> OutputDescription<Proof> {
    /// Drops to the encoded tier.
    ///
    /// Infallible: a description cannot hold a point that fails to encode.
    pub fn compress(self) -> OutputDescriptionBytes<Proof> {
        OutputDescriptionBytes {
            cv: ValueCommitmentBytes::from(&self.cv),
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
            zkproof: self.zkproof,
        }
    }
}

impl OutputDescriptionBytes<GrothProofBytes> {
    /// Encodes this v4 Output description.
    pub fn to_bytes(&self) -> [u8; OUTPUT_DESCRIPTION_V4_SIZE] {
        let mut bytes = [0u8; OUTPUT_DESCRIPTION_V4_SIZE];

        bytes[OUTPUT_V4_PREFIX].copy_from_slice(&self.to_v5().to_bytes());
        bytes[OUTPUT_V4_ZKPROOF].copy_from_slice(&self.zkproof);

        bytes
    }

    /// Decodes a v4 Output description, checking the `cmu` encoding.
    pub fn from_bytes(
        bytes: &[u8; OUTPUT_DESCRIPTION_V4_SIZE],
    ) -> Result<Self, DescriptionParseError> {
        let prefix: &[u8; OUTPUT_DESCRIPTION_V5_SIZE] = bytes[OUTPUT_V4_PREFIX]
            .try_into()
            .expect("the prefix range is OUTPUT_DESCRIPTION_V5_SIZE bytes");

        Ok(OutputDescriptionV5Bytes::from_bytes(prefix)?.into_v4(
            bytes[OUTPUT_V4_ZKPROOF]
                .try_into()
                .expect("the zkproof range is GROTH_PROOF_SIZE bytes"),
        ))
    }
}

// `zcash_client_backend`'s batch scanner bounds its queue by `Output: DynamicUsage`, and this is
// an `Output` (see the `ShieldedOutput` impl below)
impl<Proof: DynamicUsage> DynamicUsage for OutputDescriptionBytes<Proof> {
    fn dynamic_usage(&self) -> usize {
        self.zkproof.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.zkproof.dynamic_usage_bounds()
    }
}

/// Trial decryption reads `epk`, `cmu` and `enc_ciphertext`, none of which this tier keeps
/// compressed.
impl<A> ShieldedOutput<SaplingDomain, ENC_CIPHERTEXT_SIZE> for OutputDescriptionBytes<A> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.ephemeral_key.clone()
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }
}

impl<A> From<OutputDescriptionBytes<A>> for CompactOutputDescription {
    fn from(out: OutputDescriptionBytes<A>) -> CompactOutputDescription {
        CompactOutputDescription {
            ephemeral_key: out.ephemeral_key,
            cmu: out.cmu,
            enc_ciphertext: out.enc_ciphertext[..COMPACT_NOTE_SIZE]
                .try_into()
                .expect("the compact prefix is COMPACT_NOTE_SIZE bytes"),
        }
    }
}

/// An [`OutputDescriptionV5`] with `cv` left compressed.
#[derive(Clone)]
pub struct OutputDescriptionV5Bytes {
    cv: ValueCommitmentBytes,
    cmu: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

memuse::impl_no_dynamic_usage!(OutputDescriptionV5Bytes);

impl fmt::Debug for OutputDescriptionV5Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OutputDescriptionV5Bytes(cv = {:?}, cmu = {:?}, ephemeral_key = {:?})",
            self.cv, self.cmu, self.ephemeral_key
        )
    }
}

impl OutputDescriptionV5Bytes {
    pub fn cv(&self) -> &ValueCommitmentBytes {
        &self.cv
    }

    pub fn cmu(&self) -> &ExtractedNoteCommitment {
        &self.cmu
    }

    pub fn ephemeral_key(&self) -> &EphemeralKeyBytes {
        &self.ephemeral_key
    }

    /// Pairs back on the proof a v5 transaction writes in its own array.
    ///
    /// Inverse of [`OutputDescriptionBytes::to_v5`].
    pub fn into_v4(self, zkproof: GrothProofBytes) -> OutputDescriptionBytes<GrothProofBytes> {
        OutputDescriptionBytes {
            cv: self.cv,
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
            zkproof,
        }
    }

    /// Recovers the [`OutputDescriptionV5`]. 1 sqrt.
    pub fn decompress(self) -> Result<OutputDescriptionV5, DecompressionError> {
        Ok(OutputDescriptionV5::from_parts(
            self.cv
                .decompress()
                .map_err(|_| DecompressionError::InvalidValueCommitment)?,
            self.cmu,
            self.ephemeral_key,
            self.enc_ciphertext,
            self.out_ciphertext,
        ))
    }

    /// Encodes this v5 Output description.
    pub fn to_bytes(&self) -> [u8; OUTPUT_DESCRIPTION_V5_SIZE] {
        let mut bytes = [0u8; OUTPUT_DESCRIPTION_V5_SIZE];

        bytes[OUTPUT_V5_CV].copy_from_slice(&self.cv.to_bytes());
        bytes[OUTPUT_V5_CMU].copy_from_slice(&self.cmu.to_bytes());
        bytes[OUTPUT_V5_EPK].copy_from_slice(&self.ephemeral_key.0);
        bytes[OUTPUT_V5_ENC].copy_from_slice(&self.enc_ciphertext);
        bytes[OUTPUT_V5_OUT].copy_from_slice(&self.out_ciphertext);

        bytes
    }

    /// Decodes a v5 Output description, checking the `cmu` encoding.
    pub fn from_bytes(
        bytes: &[u8; OUTPUT_DESCRIPTION_V5_SIZE],
    ) -> Result<Self, DescriptionParseError> {
        let cmu = Option::from(ExtractedNoteCommitment::from_bytes(&field(
            bytes,
            OUTPUT_V5_CMU,
        )))
        .ok_or(DescriptionParseError::NonCanonicalExtractedNoteCommitment)?;

        Ok(OutputDescriptionV5Bytes {
            cv: ValueCommitmentBytes::from(field(bytes, OUTPUT_V5_CV)),
            cmu,
            ephemeral_key: EphemeralKeyBytes(field(bytes, OUTPUT_V5_EPK)),
            enc_ciphertext: bytes[OUTPUT_V5_ENC]
                .try_into()
                .expect("the enc_ciphertext range is ENC_CIPHERTEXT_SIZE bytes"),
            out_ciphertext: bytes[OUTPUT_V5_OUT]
                .try_into()
                .expect("the out_ciphertext range is OUT_CIPHERTEXT_SIZE bytes"),
        })
    }
}

impl OutputDescriptionV5 {
    /// Drops to the encoded tier.
    ///
    /// Infallible: a description cannot hold a point that fails to encode.
    pub fn compress(self) -> OutputDescriptionV5Bytes {
        OutputDescriptionV5Bytes {
            cv: ValueCommitmentBytes::from(&self.cv),
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
        }
    }
}

/// A [`Bundle`] whose descriptions are still encoded.
#[derive(Clone, Debug)]
pub struct BundleBytes<A: Authorization, V> {
    shielded_spends: Vec<SpendDescriptionBytes<A>>,
    shielded_outputs: Vec<OutputDescriptionBytes<A::OutputProof>>,
    value_balance: V,
    authorization: A,
}

impl<A: Authorization, V> BundleBytes<A, V> {
    /// `None` if it would hold neither a spend nor an output, as [`Bundle::from_parts`] does.
    pub fn from_parts(
        shielded_spends: Vec<SpendDescriptionBytes<A>>,
        shielded_outputs: Vec<OutputDescriptionBytes<A::OutputProof>>,
        value_balance: V,
        authorization: A,
    ) -> Option<Self> {
        if shielded_spends.is_empty() && shielded_outputs.is_empty() {
            None
        } else {
            Some(BundleBytes {
                shielded_spends,
                shielded_outputs,
                value_balance,
                authorization,
            })
        }
    }

    pub fn shielded_spends(&self) -> &[SpendDescriptionBytes<A>] {
        &self.shielded_spends
    }

    pub fn shielded_outputs(&self) -> &[OutputDescriptionBytes<A::OutputProof>] {
        &self.shielded_outputs
    }

    pub fn value_balance(&self) -> &V {
        &self.value_balance
    }

    pub fn authorization(&self) -> &A {
        &self.authorization
    }

    /// Recovers the [`Bundle`], naming the first description that breaks a point rule.
    pub fn decompress(self) -> Result<Bundle<A, V>, BundleDecompressionError> {
        let shielded_spends = self
            .shielded_spends
            .into_iter()
            .enumerate()
            .map(|(index, d)| {
                d.decompress()
                    .map_err(|error| BundleDecompressionError::Spend { index, error })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let shielded_outputs = self
            .shielded_outputs
            .into_iter()
            .enumerate()
            .map(|(index, o)| {
                o.decompress()
                    .map_err(|error| BundleDecompressionError::Output { index, error })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Bundle::from_parts(
            shielded_spends,
            shielded_outputs,
            self.value_balance,
            self.authorization,
        )
        .expect("a non-empty bundle decompresses to a non-empty bundle"))
    }
}

impl<A: Authorization, V> Bundle<A, V> {
    /// Drops to the encoded tier.
    ///
    /// Infallible: a [`Bundle`] cannot hold a point that fails to encode.
    pub fn compress(self) -> BundleBytes<A, V> {
        BundleBytes {
            shielded_spends: self
                .shielded_spends
                .into_iter()
                .map(SpendDescription::compress)
                .collect(),
            shielded_outputs: self
                .shielded_outputs
                .into_iter()
                .map(OutputDescription::compress)
                .collect(),
            value_balance: self.value_balance,
            authorization: self.authorization,
        }
    }
}

/// A description field that is not a valid encoding of its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DescriptionParseError {
    NonCanonicalAnchor,
    NonCanonicalExtractedNoteCommitment,
}

impl fmt::Display for DescriptionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptionParseError::NonCanonicalAnchor => {
                write!(f, "`anchor` is not a canonical field element encoding")
            }
            DescriptionParseError::NonCanonicalExtractedNoteCommitment => {
                write!(f, "`cmu` is not a canonical field element encoding")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DescriptionParseError {}

/// A description field carrying a point no valid description may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecompressionError {
    /// `cv` is not a canonical point encoding, or is of small order.
    InvalidValueCommitment,
    /// `rk` is not a canonical point encoding.
    NonCanonicalRandomizedKey,
}

impl fmt::Display for DecompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompressionError::InvalidValueCommitment => write!(
                f,
                "`cv` is not a canonical encoding of a non-small-order Jubjub point"
            ),
            DecompressionError::NonCanonicalRandomizedKey => {
                write!(f, "`rk` is not a canonical point encoding")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecompressionError {}

/// The description at `index` breaks a point rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BundleDecompressionError {
    Spend {
        index: usize,
        error: DecompressionError,
    },
    Output {
        index: usize,
        error: DecompressionError,
    },
}

impl fmt::Display for BundleDecompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleDecompressionError::Spend { index, error } => write!(f, "spend {index}: {error}"),
            BundleDecompressionError::Output { index, error } => {
                write!(f, "output {index}: {error}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BundleDecompressionError {}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ff::Field as _;
    use group::{Group as _, GroupEncoding as _};
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    use super::{
        BundleBytes, BundleDecompressionError, DecompressionError, DescriptionParseError,
        OutputDescriptionBytes, OutputDescriptionV5Bytes, SpendDescriptionBytes,
        SpendDescriptionV5Bytes, ENC_CIPHERTEXT_SIZE, OUTPUT_DESCRIPTION_V4_SIZE,
        OUTPUT_DESCRIPTION_V5_SIZE, SPEND_DESCRIPTION_V4_SIZE,
    };
    use crate::{
        bundle::{testing::arb_bundle, Authorized, Bundle, GrothProofBytes},
        keys::{Diversifier, PreparedIncomingViewingKey, SaplingIvk},
        note_encryption::{
            sapling_note_encryption, try_sapling_compact_note_decryption,
            try_sapling_note_decryption, CompactOutputDescription, Zip212Enforcement,
        },
        util::generate_random_rseed,
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueCommitmentBytes},
        Note,
    };

    // Not a canonical encoding of any Jubjub point, nor of any bls12_381 scalar
    const NON_CANONICAL: [u8; 32] = [0xff; 32];

    fn small_order_cv() -> ValueCommitmentBytes {
        ValueCommitmentBytes::from(jubjub::ExtendedPoint::identity().to_bytes())
    }

    fn valid_cv() -> ValueCommitmentBytes {
        ValueCommitmentBytes::from(jubjub::ExtendedPoint::generator().to_bytes())
    }

    fn spend_with(cv: ValueCommitmentBytes, rk: [u8; 32]) -> SpendDescriptionBytes<Authorized> {
        let mut bytes = [0u8; SPEND_DESCRIPTION_V4_SIZE];
        bytes[0..32].copy_from_slice(&cv.to_bytes());
        bytes[96..128].copy_from_slice(&rk);

        SpendDescriptionBytes::from_bytes(&bytes).expect("a zero anchor is canonical")
    }

    fn descriptions(
        bundle: Bundle<Authorized, i64>,
    ) -> (
        Vec<SpendDescriptionBytes<Authorized>>,
        Vec<OutputDescriptionBytes<GrothProofBytes>>,
    ) {
        let bytes = bundle.compress();
        (
            bytes.shielded_spends().to_vec(),
            bytes.shielded_outputs().to_vec(),
        )
    }

    /// The `cv` and `rk` rules are `decompress`'s, so a description breaking either still
    /// parses.
    #[test]
    fn spend_decompress_enforces_the_point_rules() {
        let valid_rk = jubjub::ExtendedPoint::generator().to_bytes();

        assert!(spend_with(valid_cv(), valid_rk).decompress().is_ok());

        for (spend, expected) in [
            (
                spend_with(valid_cv(), NON_CANONICAL),
                DecompressionError::NonCanonicalRandomizedKey,
            ),
            (
                spend_with(ValueCommitmentBytes::from(NON_CANONICAL), valid_rk),
                DecompressionError::InvalidValueCommitment,
            ),
            // Canonical, but small order, which no valid description may carry
            (
                spend_with(small_order_cv(), valid_rk),
                DecompressionError::InvalidValueCommitment,
            ),
        ] {
            assert_eq!(spend.decompress().unwrap_err(), expected);
        }
    }

    #[test]
    fn from_bytes_rejects_non_canonical_field_elements() {
        let mut spend = [0u8; SPEND_DESCRIPTION_V4_SIZE];
        spend[32..64].copy_from_slice(&NON_CANONICAL);
        assert_eq!(
            SpendDescriptionBytes::<Authorized>::from_bytes(&spend).unwrap_err(),
            DescriptionParseError::NonCanonicalAnchor,
        );

        let mut output = [0u8; OUTPUT_DESCRIPTION_V4_SIZE];
        output[32..64].copy_from_slice(&NON_CANONICAL);
        assert_eq!(
            OutputDescriptionBytes::from_bytes(&output).unwrap_err(),
            DescriptionParseError::NonCanonicalExtractedNoteCommitment,
        );
    }

    #[test]
    fn from_parts_rejects_an_empty_bundle() {
        assert!(BundleBytes::<Authorized, i64>::from_parts(
            Vec::new(),
            Vec::new(),
            0,
            Authorized {
                binding_sig: redjubjub::Signature::from([0u8; 64]),
            },
        )
        .is_none());
    }

    /// Trial decryption must succeed on an output whose `cv` is garbage — the proof that it
    /// decompresses nothing.
    #[test]
    fn trial_decryption_needs_no_decompression() {
        let mut rng = OsRng;
        let enforcement = Zip212Enforcement::On;

        let ivk = SaplingIvk(jubjub::Fr::random(&mut rng));
        let prepared_ivk = PreparedIncomingViewingKey::new(&ivk);
        let recipient = ivk
            .to_payment_address(Diversifier([0; 11]))
            .expect("the zero diversifier is valid for this ivk");

        let value = NoteValue::from_raw(100);
        let note: Note = recipient.create_note(value, generate_random_rseed(enforcement, &mut rng));
        let cmu = note.cmu();
        let memo = [0x37; 512];

        let encryptor = sapling_note_encryption(None, note.clone(), memo, &mut rng);
        let epk = encryptor.epk().to_bytes();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(
            &ValueCommitment::derive(value, ValueCommitTrapdoor::random(&mut rng)),
            &cmu,
            &mut rng,
        );

        // `cv` undecodable, so anything that decompressed it would fail here
        let mut encoded = [0u8; OUTPUT_DESCRIPTION_V4_SIZE];
        encoded[0..32].copy_from_slice(&NON_CANONICAL);
        encoded[32..64].copy_from_slice(&cmu.to_bytes());
        encoded[64..96].copy_from_slice(&epk.0);
        encoded[96..96 + ENC_CIPHERTEXT_SIZE].copy_from_slice(&enc_ciphertext);
        encoded[96 + ENC_CIPHERTEXT_SIZE..OUTPUT_DESCRIPTION_V5_SIZE]
            .copy_from_slice(&out_ciphertext);
        let output = OutputDescriptionBytes::from_bytes(&encoded).expect("`cmu` is canonical");

        assert_eq!(
            output.clone().decompress().unwrap_err(),
            DecompressionError::InvalidValueCommitment
        );

        assert_eq!(
            try_sapling_note_decryption(&prepared_ivk, &output, enforcement)
                .map(|(n, _, m)| (n, m)),
            Some((note.clone(), memo)),
        );
        assert_eq!(
            try_sapling_compact_note_decryption(
                &prepared_ivk,
                &CompactOutputDescription::from(output),
                enforcement,
            )
            .map(|(n, _)| n),
            Some(note),
        );
    }

    proptest! {
        /// A description written and read back is the same description, and the point tier it
        /// decompresses to re-encodes identically.
        #[test]
        fn descriptions_round_trip(bundle in arb_bundle(0i64)) {
            let Some(bundle) = bundle else { return Ok(()) };
            let (spends, outputs) = descriptions(bundle);

            for spend in spends {
                let encoded = spend.to_bytes();
                prop_assert_eq!(
                    SpendDescriptionBytes::<Authorized>::from_bytes(&encoded)
                        .expect("a written description reads back")
                        .to_bytes(),
                    encoded
                );

                let recovered = spend.decompress().expect("a derived cv is not small order");
                prop_assert_eq!(recovered.compress().to_bytes(), encoded);
            }

            for output in outputs {
                let encoded = output.to_bytes();
                prop_assert_eq!(
                    OutputDescriptionBytes::from_bytes(&encoded)
                        .expect("a written description reads back")
                        .to_bytes(),
                    encoded
                );

                let recovered = output.decompress().expect("a derived cv is not small order");
                prop_assert_eq!(recovered.compress().to_bytes(), encoded);
            }
        }

        /// A v5 transaction splits a description across its arrays, so reassembly must land on
        /// the bytes the v4 encoding would have written.
        #[test]
        fn v5_reassembly_matches_the_v4_encoding(bundle in arb_bundle(0i64)) {
            let Some(bundle) = bundle else { return Ok(()) };
            let (spends, outputs) = descriptions(bundle);

            for spend in spends {
                let v5 = spend.to_v5();
                prop_assert_eq!(
                    SpendDescriptionV5Bytes::from_bytes(&v5.to_bytes()).to_bytes(),
                    v5.to_bytes()
                );

                let reassembled: SpendDescriptionBytes<Authorized> = v5.into_v4(
                    *spend.anchor(),
                    *spend.zkproof(),
                    *spend.spend_auth_sig(),
                );
                prop_assert_eq!(reassembled.to_bytes(), spend.to_bytes());
            }

            for output in outputs {
                let v5 = output.to_v5();
                prop_assert_eq!(
                    OutputDescriptionV5Bytes::from_bytes(&v5.to_bytes())
                        .expect("a written description reads back")
                        .to_bytes(),
                    v5.to_bytes()
                );

                prop_assert_eq!(
                    v5.into_v4(*output.zkproof()).to_bytes(),
                    output.to_bytes()
                );
            }
        }

        #[test]
        fn bundle_round_trips_and_names_the_offending_spend(bundle in arb_bundle(0i64)) {
            let Some(bundle) = bundle else { return Ok(()) };
            let (spends, outputs) = descriptions(bundle.clone());

            let recovered = bundle.compress()
                .decompress()
                .expect("a built bundle's points are all valid");
            let (after_spends, after_outputs) = descriptions(recovered);

            prop_assert_eq!(
                spends.iter().map(|s| s.to_bytes()).collect::<Vec<_>>(),
                after_spends.iter().map(|s| s.to_bytes()).collect::<Vec<_>>()
            );
            prop_assert_eq!(
                outputs.iter().map(|o| o.to_bytes()).collect::<Vec<_>>(),
                after_outputs.iter().map(|o| o.to_bytes()).collect::<Vec<_>>()
            );

            if let Some(last) = spends.len().checked_sub(1) {
                let mut tampered = spends;
                tampered[last] = spend_with(small_order_cv(), NON_CANONICAL);

                prop_assert_eq!(
                    BundleBytes::<Authorized, i64>::from_parts(
                        tampered,
                        outputs,
                        0,
                        Authorized {
                            binding_sig: redjubjub::Signature::from([0u8; 64]),
                        },
                    )
                    .expect("the bundle is non-empty")
                    .decompress()
                    .unwrap_err(),
                    BundleDecompressionError::Spend {
                        index: last,
                        error: DecompressionError::InvalidValueCommitment,
                    }
                );
            }
        }
    }
}
