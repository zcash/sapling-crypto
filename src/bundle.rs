use alloc::vec::Vec;
use core::fmt::Debug;

use memuse::DynamicUsage;

use redjubjub::{Binding, SpendAuth};

use zcash_note_encryption::{
    note_bytes::NoteBytesData, EphemeralKeyBytes, ShieldedOutput, OUT_CIPHERTEXT_SIZE,
};

use crate::{
    constants::GROTH_PROOF_SIZE,
    note::ExtractedNoteCommitment,
    note_encryption::{
        CompactOutputDescription, NoteCiphertextBytes, SaplingDomain, COMPACT_NOTE_SIZE,
        ENC_CIPHERTEXT_SIZE,
    },
    value::ValueCommitment,
    Nullifier,
};

pub type GrothProofBytes = [u8; GROTH_PROOF_SIZE];

/// Defines the authorization type of a Sapling bundle.
pub trait Authorization: Debug {
    /// Tree root representation; complete states require a concrete root.
    type Anchor: Copy + Debug + Into<Option<bls12_381::Scalar>>;
    type SpendProof: Clone + Debug;
    type OutputProof: Clone + Debug;
    type AuthSig: Clone + Debug;
}

/// Marker type for effects without proofs or signatures.
///
/// Spend anchors are `None` when authorizing data was pruned, and `Some` when
/// the transaction format commits to them as effects.
#[derive(Clone, Copy, Debug)]
pub struct EffectsOnly;

impl Authorization for EffectsOnly {
    type Anchor = Option<bls12_381::Scalar>;
    type SpendProof = ();
    type OutputProof = ();
    type AuthSig = ();
}

/// Authorizing data for a bundle of Sapling spends and outputs, ready to be committed to
/// the ledger.
///
/// Complete spends cannot carry an absent anchor:
/// ```compile_fail
/// use sapling_crypto::{Bundle, bundle::Authorized};
/// fn remove_anchors(bundle: Bundle<Authorized, i64>) -> Bundle<Authorized, i64> {
///     bundle.map_authorization_with_anchor(
///         (), |_, _| None, |_, proof| proof, |_, proof| proof,
///         |_, signature| signature, |_, auth| auth,
///     )
/// }
/// ```
#[derive(Debug, Copy, Clone)]
pub struct Authorized {
    // TODO: Make this private.
    pub binding_sig: redjubjub::Signature<Binding>,
}

impl Authorization for Authorized {
    type Anchor = bls12_381::Scalar;
    type SpendProof = GrothProofBytes;
    type OutputProof = GrothProofBytes;
    type AuthSig = redjubjub::Signature<SpendAuth>;
}

#[derive(Debug, Clone)]
pub struct Bundle<A: Authorization, V> {
    shielded_spends: Vec<SpendDescription<A>>,
    shielded_outputs: Vec<OutputDescription<A::OutputProof>>,
    value_balance: V,
    authorization: A,
}

impl<A: Authorization, V> Bundle<A, V> {
    /// Constructs a `Bundle` from its constituent parts.
    pub fn from_parts(
        shielded_spends: Vec<SpendDescription<A>>,
        shielded_outputs: Vec<OutputDescription<A::OutputProof>>,
        value_balance: V,
        authorization: A,
    ) -> Option<Self> {
        if shielded_spends.is_empty() && shielded_outputs.is_empty() {
            None
        } else {
            Some(Bundle {
                shielded_spends,
                shielded_outputs,
                value_balance,
                authorization,
            })
        }
    }

    /// Returns the list of spends in this bundle.
    pub fn shielded_spends(&self) -> &[SpendDescription<A>] {
        &self.shielded_spends
    }

    /// Returns the list of outputs in this bundle.
    pub fn shielded_outputs(&self) -> &[OutputDescription<A::OutputProof>] {
        &self.shielded_outputs
    }

    /// Returns the net value moved into or out of the Sapling shielded pool.
    ///
    /// This is the sum of Sapling spends minus the sum of Sapling outputs.
    pub fn value_balance(&self) -> &V {
        &self.value_balance
    }

    /// Returns the authorization for this bundle.
    ///
    /// In the case of a `Bundle<Authorized>`, this is the binding signature.
    pub fn authorization(&self) -> &A {
        &self.authorization
    }

    /// Transitions this bundle from one authorization state to another.
    pub fn map_authorization<R, B>(
        self,
        context: R,
        spend_proof: impl Fn(&mut R, A::SpendProof) -> B::SpendProof,
        output_proof: impl Fn(&mut R, A::OutputProof) -> B::OutputProof,
        auth_sig: impl Fn(&mut R, A::AuthSig) -> B::AuthSig,
        auth: impl FnOnce(&mut R, A) -> B,
    ) -> Bundle<B, V>
    where
        B: Authorization<Anchor = A::Anchor>,
    {
        self.map_authorization_with_anchor(
            context,
            |_, anchor| anchor,
            spend_proof,
            output_proof,
            auth_sig,
            auth,
        )
    }

    /// Transitions authorization and maps each spend's anchor representation.
    pub fn map_authorization_with_anchor<R, B: Authorization>(
        self,
        mut context: R,
        anchor: impl Fn(&mut R, A::Anchor) -> B::Anchor,
        spend_proof: impl Fn(&mut R, A::SpendProof) -> B::SpendProof,
        output_proof: impl Fn(&mut R, A::OutputProof) -> B::OutputProof,
        auth_sig: impl Fn(&mut R, A::AuthSig) -> B::AuthSig,
        auth: impl FnOnce(&mut R, A) -> B,
    ) -> Bundle<B, V> {
        Bundle {
            shielded_spends: self
                .shielded_spends
                .into_iter()
                .map(|d| SpendDescription {
                    cv: d.cv,
                    anchor: anchor(&mut context, d.anchor),
                    nullifier: d.nullifier,
                    rk: d.rk,
                    zkproof: spend_proof(&mut context, d.zkproof),
                    spend_auth_sig: auth_sig(&mut context, d.spend_auth_sig),
                })
                .collect(),
            shielded_outputs: self
                .shielded_outputs
                .into_iter()
                .map(|o| OutputDescription {
                    cv: o.cv,
                    cmu: o.cmu,
                    ephemeral_key: o.ephemeral_key,
                    enc_ciphertext: o.enc_ciphertext,
                    out_ciphertext: o.out_ciphertext,
                    zkproof: output_proof(&mut context, o.zkproof),
                })
                .collect(),
            value_balance: self.value_balance,
            authorization: auth(&mut context, self.authorization),
        }
    }

    /// Transitions this bundle from one authorization state to another.
    pub fn try_map_authorization<R, B, Error>(
        self,
        context: R,
        spend_proof: impl Fn(&mut R, A::SpendProof) -> Result<B::SpendProof, Error>,
        output_proof: impl Fn(&mut R, A::OutputProof) -> Result<B::OutputProof, Error>,
        auth_sig: impl Fn(&mut R, A::AuthSig) -> Result<B::AuthSig, Error>,
        auth: impl Fn(&mut R, A) -> Result<B, Error>,
    ) -> Result<Bundle<B, V>, Error>
    where
        B: Authorization<Anchor = A::Anchor>,
    {
        self.try_map_authorization_with_anchor(
            context,
            |_, anchor| Ok(anchor),
            spend_proof,
            output_proof,
            auth_sig,
            auth,
        )
    }

    /// Transitions authorization and maps anchors, returning the first mapping error.
    pub fn try_map_authorization_with_anchor<R, B: Authorization, Error>(
        self,
        mut context: R,
        anchor: impl Fn(&mut R, A::Anchor) -> Result<B::Anchor, Error>,
        spend_proof: impl Fn(&mut R, A::SpendProof) -> Result<B::SpendProof, Error>,
        output_proof: impl Fn(&mut R, A::OutputProof) -> Result<B::OutputProof, Error>,
        auth_sig: impl Fn(&mut R, A::AuthSig) -> Result<B::AuthSig, Error>,
        auth: impl Fn(&mut R, A) -> Result<B, Error>,
    ) -> Result<Bundle<B, V>, Error> {
        Ok(Bundle {
            shielded_spends: self
                .shielded_spends
                .into_iter()
                .map(|d| {
                    Ok(SpendDescription {
                        cv: d.cv,
                        anchor: anchor(&mut context, d.anchor)?,
                        nullifier: d.nullifier,
                        rk: d.rk,
                        zkproof: spend_proof(&mut context, d.zkproof)?,
                        spend_auth_sig: auth_sig(&mut context, d.spend_auth_sig)?,
                    })
                })
                .collect::<Result<_, _>>()?,
            shielded_outputs: self
                .shielded_outputs
                .into_iter()
                .map(|o| {
                    Ok(OutputDescription {
                        cv: o.cv,
                        cmu: o.cmu,
                        ephemeral_key: o.ephemeral_key,
                        enc_ciphertext: o.enc_ciphertext,
                        out_ciphertext: o.out_ciphertext,
                        zkproof: output_proof(&mut context, o.zkproof)?,
                    })
                })
                .collect::<Result<_, _>>()?,
            value_balance: self.value_balance,
            authorization: auth(&mut context, self.authorization)?,
        })
    }
}

impl<V: DynamicUsage> DynamicUsage for Bundle<Authorized, V> {
    fn dynamic_usage(&self) -> usize {
        self.shielded_spends.dynamic_usage()
            + self.shielded_outputs.dynamic_usage()
            + self.value_balance.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let bounds = (
            self.shielded_spends.dynamic_usage_bounds(),
            self.shielded_outputs.dynamic_usage_bounds(),
            self.value_balance.dynamic_usage_bounds(),
        );

        (
            bounds.0 .0 + bounds.1 .0 + bounds.2 .0,
            bounds
                .0
                 .1
                .zip(bounds.1 .1)
                .zip(bounds.2 .1)
                .map(|((a, b), c)| a + b + c),
        )
    }
}

#[derive(Clone)]
pub struct SpendDescription<A: Authorization> {
    cv: ValueCommitment,
    anchor: A::Anchor,
    nullifier: Nullifier,
    rk: redjubjub::VerificationKey<SpendAuth>,
    zkproof: A::SpendProof,
    spend_auth_sig: A::AuthSig,
}

impl<A: Authorization> core::fmt::Debug for SpendDescription<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "SpendDescription(cv = {:?}, anchor = {:?}, nullifier = {:?}, rk = {:?}, spend_auth_sig = {:?})",
            self.cv, self.anchor, self.nullifier, self.rk, self.spend_auth_sig
        )
    }
}

impl<A: Authorization> SpendDescription<A> {
    /// Constructs a spend from its typed fields and authorization-selected anchor.
    pub fn from_parts(
        cv: ValueCommitment,
        anchor: A::Anchor,
        nullifier: Nullifier,
        rk: redjubjub::VerificationKey<SpendAuth>,
        zkproof: A::SpendProof,
        spend_auth_sig: A::AuthSig,
    ) -> Self {
        Self {
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        }
    }

    /// Returns the commitment to the value consumed by this spend.
    pub fn cv(&self) -> &ValueCommitment {
        &self.cv
    }

    /// Returns the root representation selected by the authorization state.
    ///
    /// Complete states return a concrete root. Effects-only spends may omit it.
    pub fn anchor(&self) -> &A::Anchor {
        &self.anchor
    }

    /// Returns the nullifier of the note being spent.
    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }

    /// Returns the randomized verification key for the note being spent.
    pub fn rk(&self) -> &redjubjub::VerificationKey<SpendAuth> {
        &self.rk
    }

    /// Returns the proof for this spend.
    pub fn zkproof(&self) -> &A::SpendProof {
        &self.zkproof
    }

    /// Returns the authorization signature for this spend.
    pub fn spend_auth_sig(&self) -> &A::AuthSig {
        &self.spend_auth_sig
    }
}

#[cfg(test)]
mod anchor_tests {
    use super::{testing::arb_bundle, Authorized, EffectsOnly};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn native_effects_allow_absent_anchors(bundle in arb_bundle(0i64)) {
            if let Some(bundle) = bundle {
                for spend in bundle.shielded_spends() {
                    let _: &bls12_381::Scalar = spend.anchor();
                }
                let effects = bundle.clone().map_authorization_with_anchor(
                    (), |_, _| None, |_, _| (), |_, _| (), |_, _| (), |_, _| EffectsOnly,
                );
                prop_assert_eq!(effects.shielded_spends().len(), bundle.shielded_spends().len());
                for (effect, spend) in effects.shielded_spends().iter().zip(bundle.shielded_spends()) {
                    prop_assert!(effect.anchor().is_none());
                    prop_assert_eq!(effect.nullifier(), spend.nullifier());
                    prop_assert_eq!(effect.cv().to_bytes(), spend.cv().to_bytes());
                }
                let retained = bundle.map_authorization_with_anchor(
                    (), |_, anchor| Some(anchor), |_, _| (), |_, _| (), |_, _| (), |_, _| EffectsOnly,
                );
                for spend in retained.shielded_spends() {
                    prop_assert!(spend.anchor().is_some());
                }
                let result = effects.try_map_authorization_with_anchor::<_, Authorized, ()>(
                    (), |_, anchor| anchor.ok_or(()), |_, _| Ok([0; crate::constants::GROTH_PROOF_SIZE]),
                    |_, _| Ok([0; crate::constants::GROTH_PROOF_SIZE]),
                    |_, _| Ok(redjubjub::Signature::from([0; 64])),
                    |_, _| Ok(Authorized { binding_sig: redjubjub::Signature::from([0; 64]) }),
                );
                prop_assert_eq!(result.is_err(), !retained.shielded_spends().is_empty());
            }
        }
    }
}

impl DynamicUsage for SpendDescription<Authorized> {
    fn dynamic_usage(&self) -> usize {
        self.zkproof.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.zkproof.dynamic_usage_bounds()
    }
}

#[derive(Clone)]
pub struct SpendDescriptionV5 {
    cv: ValueCommitment,
    nullifier: Nullifier,
    rk: redjubjub::VerificationKey<SpendAuth>,
}

impl SpendDescriptionV5 {
    /// Constructs a v5 `SpendDescription` from its constituent parts.
    pub fn from_parts(
        cv: ValueCommitment,
        nullifier: Nullifier,
        rk: redjubjub::VerificationKey<SpendAuth>,
    ) -> Self {
        Self { cv, nullifier, rk }
    }

    pub fn into_spend_description<A>(
        self,
        anchor: bls12_381::Scalar,
        zkproof: GrothProofBytes,
        spend_auth_sig: redjubjub::Signature<SpendAuth>,
    ) -> SpendDescription<A>
    where
        A: Authorization<
            Anchor = bls12_381::Scalar,
            SpendProof = GrothProofBytes,
            AuthSig = redjubjub::Signature<SpendAuth>,
        >,
    {
        SpendDescription {
            cv: self.cv,
            anchor,
            nullifier: self.nullifier,
            rk: self.rk,
            zkproof,
            spend_auth_sig,
        }
    }
}

#[derive(Clone)]
pub struct OutputDescription<Proof> {
    cv: ValueCommitment,
    cmu: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: NoteCiphertextBytes,
    out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    zkproof: Proof,
}

impl<Proof> OutputDescription<Proof> {
    /// Returns the commitment to the value consumed by this output.
    pub fn cv(&self) -> &ValueCommitment {
        &self.cv
    }

    /// Returns the commitment to the new note being created.
    pub fn cmu(&self) -> &ExtractedNoteCommitment {
        &self.cmu
    }

    pub fn ephemeral_key(&self) -> &EphemeralKeyBytes {
        &self.ephemeral_key
    }

    /// Returns the encrypted note ciphertext.
    pub fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext.0
    }

    /// Returns the output recovery ciphertext.
    pub fn out_ciphertext(&self) -> &[u8; OUT_CIPHERTEXT_SIZE] {
        &self.out_ciphertext
    }

    /// Returns the proof for this output.
    pub fn zkproof(&self) -> &Proof {
        &self.zkproof
    }

    /// Constructs a v4 `OutputDescription` from its constituent parts.
    pub fn from_parts(
        cv: ValueCommitment,
        cmu: ExtractedNoteCommitment,
        ephemeral_key: EphemeralKeyBytes,
        enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
        zkproof: Proof,
    ) -> Self {
        OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext: NoteBytesData(enc_ciphertext),
            out_ciphertext,
            zkproof,
        }
    }
}

#[cfg(test)]
impl<Proof> OutputDescription<Proof> {
    pub(crate) fn cv_mut(&mut self) -> &mut ValueCommitment {
        &mut self.cv
    }
    pub(crate) fn cmu_mut(&mut self) -> &mut ExtractedNoteCommitment {
        &mut self.cmu
    }
    pub(crate) fn ephemeral_key_mut(&mut self) -> &mut EphemeralKeyBytes {
        &mut self.ephemeral_key
    }
    pub(crate) fn enc_ciphertext_mut(&mut self) -> &mut [u8; ENC_CIPHERTEXT_SIZE] {
        &mut self.enc_ciphertext.0
    }
    pub(crate) fn out_ciphertext_mut(&mut self) -> &mut [u8; OUT_CIPHERTEXT_SIZE] {
        &mut self.out_ciphertext
    }
}

impl<Proof: DynamicUsage> DynamicUsage for OutputDescription<Proof> {
    fn dynamic_usage(&self) -> usize {
        self.zkproof.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.zkproof.dynamic_usage_bounds()
    }
}

impl<A> ShieldedOutput<SaplingDomain> for OutputDescription<A> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.ephemeral_key.clone()
    }

    fn cmstar(&self) -> &ExtractedNoteCommitment {
        &self.cmu
    }

    fn enc_ciphertext(&self) -> Option<&NoteCiphertextBytes> {
        Some(&self.enc_ciphertext)
    }

    fn enc_ciphertext_compact(&self) -> NoteBytesData<COMPACT_NOTE_SIZE> {
        NoteBytesData(
            self.enc_ciphertext.0[..COMPACT_NOTE_SIZE]
                .try_into()
                .expect("slice is the correct length"),
        )
    }
}

impl<A> core::fmt::Debug for OutputDescription<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "OutputDescription(cv = {:?}, cmu = {:?}, ephemeral_key = {:?})",
            self.cv, self.cmu, self.ephemeral_key
        )
    }
}

#[derive(Clone)]
pub struct OutputDescriptionV5 {
    cv: ValueCommitment,
    cmu: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

memuse::impl_no_dynamic_usage!(OutputDescriptionV5);

impl OutputDescriptionV5 {
    /// Constructs a v5 `OutputDescription` from its constituent parts.
    pub fn from_parts(
        cv: ValueCommitment,
        cmu: ExtractedNoteCommitment,
        ephemeral_key: EphemeralKeyBytes,
        enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    ) -> Self {
        Self {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        }
    }

    pub fn into_output_description(
        self,
        zkproof: GrothProofBytes,
    ) -> OutputDescription<GrothProofBytes> {
        OutputDescription {
            cv: self.cv,
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key,
            enc_ciphertext: NoteBytesData(self.enc_ciphertext),
            out_ciphertext: self.out_ciphertext,
            zkproof,
        }
    }
}

impl<A> From<OutputDescription<A>> for CompactOutputDescription {
    fn from(out: OutputDescription<A>) -> CompactOutputDescription {
        CompactOutputDescription {
            ephemeral_key: out.ephemeral_key,
            cmu: out.cmu,
            enc_ciphertext: out.enc_ciphertext.0[..COMPACT_NOTE_SIZE]
                .try_into()
                .unwrap(),
        }
    }
}

#[cfg(test)]
pub(crate) fn binding_verification_key<V: Copy + Into<i64>>(
    bundle: &Bundle<Authorized, V>,
) -> redjubjub::VerificationKey<redjubjub::Binding> {
    use crate::value::CommitmentSum;

    let spends = bundle
        .shielded_spends()
        .iter()
        .map(|spend| spend.cv())
        .sum::<CommitmentSum>();
    let outputs = bundle
        .shielded_outputs()
        .iter()
        .map(|output| output.cv())
        .sum::<CommitmentSum>();
    (spends - outputs).into_bvk(*bundle.value_balance())
}

#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use core::fmt;

    use ff::Field;
    use group::{Group, GroupEncoding};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        constants::GROTH_PROOF_SIZE,
        note::testing::arb_cmu,
        value::{
            testing::{arb_note_value_bounded, arb_trapdoor},
            ValueCommitment, MAX_NOTE_VALUE,
        },
        Nullifier,
    };

    use super::{
        Authorized, Bundle, GrothProofBytes, NoteBytesData, OutputDescription, SpendDescription,
        ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE,
    };

    prop_compose! {
        fn arb_extended_point()(rng_seed in prop::array::uniform32(any::<u8>())) -> jubjub::ExtendedPoint {
            let mut rng = StdRng::from_seed(rng_seed);
            let scalar = jubjub::Scalar::random(&mut rng);
            jubjub::ExtendedPoint::generator() * scalar
        }
    }

    prop_compose! {
        /// produce a spend description with invalid data (useful only for serialization
        /// roundtrip testing).
        fn arb_spend_description(n_spends: usize)(
            value in arb_note_value_bounded(MAX_NOTE_VALUE.checked_div(n_spends as u64).unwrap_or(0)),
            rcv in arb_trapdoor(),
            anchor in vec(any::<u8>(), 64)
                .prop_map(|v| <[u8;64]>::try_from(v.as_slice()).unwrap())
                .prop_map(|v| bls12_381::Scalar::from_bytes_wide(&v)),
            nullifier in prop::array::uniform32(any::<u8>())
                .prop_map(|v| Nullifier::from_slice(&v).unwrap()),
            zkproof in vec(any::<u8>(), GROTH_PROOF_SIZE)
                .prop_map(|v| <[u8;GROTH_PROOF_SIZE]>::try_from(v.as_slice()).unwrap()),
            rng_seed in prop::array::uniform32(prop::num::u8::ANY),
            fake_sighash_bytes in prop::array::uniform32(prop::num::u8::ANY),
        ) -> SpendDescription<Authorized> {
            let mut rng = StdRng::from_seed(rng_seed);
            let sk1 = redjubjub::SigningKey::new(&mut rng);
            let rk = redjubjub::VerificationKey::from(&sk1);
            let cv = ValueCommitment::derive(value, rcv);
            SpendDescription {
                cv,
                anchor,
                nullifier,
                rk,
                zkproof,
                spend_auth_sig: sk1.sign(&mut rng, &fake_sighash_bytes),
            }
        }
    }

    prop_compose! {
        /// produce an output description with invalid data (useful only for serialization
        /// roundtrip testing).
        pub fn arb_output_description(n_outputs: usize)(
            value in arb_note_value_bounded(MAX_NOTE_VALUE.checked_div(n_outputs as u64).unwrap_or(0)),
            rcv in arb_trapdoor(),
            cmu in arb_cmu(),
            enc_ciphertext in vec(any::<u8>(), ENC_CIPHERTEXT_SIZE)
                .prop_map(|v| <[u8; ENC_CIPHERTEXT_SIZE]>::try_from(v.as_slice()).unwrap()),
            epk in arb_extended_point(),
            out_ciphertext in vec(any::<u8>(), OUT_CIPHERTEXT_SIZE)
                .prop_map(|v| <[u8; OUT_CIPHERTEXT_SIZE]>::try_from(v.as_slice()).unwrap()),
            zkproof in vec(any::<u8>(), GROTH_PROOF_SIZE)
                .prop_map(|v| <[u8; GROTH_PROOF_SIZE]>::try_from(v.as_slice()).unwrap()),
        ) -> OutputDescription<GrothProofBytes> {
            let cv = ValueCommitment::derive(value, rcv);
            OutputDescription {
                cv,
                cmu,
                ephemeral_key: epk.to_bytes().into(),
                enc_ciphertext: NoteBytesData(enc_ciphertext),
                out_ciphertext,
                zkproof,
            }
        }
    }

    pub fn arb_bundle<V: Copy + fmt::Debug + 'static>(
        value_balance: V,
    ) -> impl Strategy<Value = Option<Bundle<Authorized, V>>> {
        (0usize..30, 0usize..30)
            .prop_flat_map(|(n_spends, n_outputs)| {
                (
                    vec(arb_spend_description(n_spends), n_spends),
                    vec(arb_output_description(n_outputs), n_outputs),
                    prop::array::uniform32(prop::num::u8::ANY),
                    prop::array::uniform32(prop::num::u8::ANY),
                )
            })
            .prop_map(
                move |(shielded_spends, shielded_outputs, rng_seed, fake_bvk_bytes)| {
                    if shielded_spends.is_empty() && shielded_outputs.is_empty() {
                        None
                    } else {
                        let mut rng = StdRng::from_seed(rng_seed);
                        let bsk = redjubjub::SigningKey::new(&mut rng);

                        Some(Bundle {
                            shielded_spends,
                            shielded_outputs,
                            value_balance,
                            authorization: Authorized {
                                binding_sig: bsk.sign(&mut rng, &fake_bvk_bytes),
                            },
                        })
                    }
                },
            )
    }
}
