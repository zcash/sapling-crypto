//! Monetary values within the Sapling shielded pool.
//!
//! Values are represented in three places within the Sapling protocol:
//! - [`NoteValue`], the value of an individual note. It is an unsigned 64-bit integer
//!   (with maximum value [`MAX_NOTE_VALUE`]), and is serialized in a note plaintext.
//! - [`ValueSum`], the sum of note values within a Sapling [`Bundle`]. It is represented
//!   as an `i128` and places an upper bound on the maximum number of notes within a
//!   single [`Bundle`].
//! - `valueBalanceSapling`, which is a signed 63-bit integer. This is represented
//!   by a user-defined type parameter on [`Bundle`], returned by
//!   [`Bundle::value_balance`] and [`Builder::value_balance`].
//!
//! If your specific instantiation of the Sapling protocol requires a smaller bound on
//! valid note values (for example, Zcash's `MAX_MONEY` fits into a 51-bit integer), you
//! should enforce this in two ways:
//!
//! - Define your `valueBalanceSapling` type to enforce your valid value range. This can
//!   be checked in its `TryFrom<i64>` implementation.
//! - Define your own "amount" type for note values, and convert it to `NoteValue` prior
//!   to calling [`Builder::add_output`].
//!
//! Inside the circuit, note values are constrained to be unsigned 64-bit integers.
//!
//! # Caution!
//!
//! An `i64` is _not_ a signed 64-bit integer! The [Rust documentation] calls `i64` the
//! 64-bit signed integer type, which is true in the sense that its encoding in memory
//! takes up 64 bits. Numerically, however, `i64` is a signed 63-bit integer.
//!
//! Fortunately, users of this crate should never need to construct [`ValueSum`] directly;
//! you should only need to interact with [`NoteValue`] (which can be safely constructed
//! from a `u64`) and `valueBalanceSapling` (which can be represented as an `i64`).
//!
//! [`Bundle`]: crate::Bundle
//! [`Bundle::value_balance`]: crate::Bundle::value_balance
//! [`Builder::value_balance`]: crate::builder::Builder::value_balance
//! [`Builder::add_output`]: crate::builder::Builder::add_output
//! [Rust documentation]: https://doc.rust-lang.org/stable/std/primitive.i64.html

use bitvec::{array::BitArray, order::Lsb0};
use ff::{Field, PrimeField};
use group::GroupEncoding;
use rand::RngCore;
use subtle::CtOption;

use super::constants::{VALUE_COMMITMENT_RANDOMNESS_GENERATOR, VALUE_COMMITMENT_VALUE_GENERATOR};
use crate::primitives::{decompress_not_small_order, InvalidPoint};

mod sums;
pub use sums::{BalanceError, CommitmentSum, TrapdoorSum, ValueSum};

/// Maximum note value.
pub const MAX_NOTE_VALUE: u64 = u64::MAX;

/// The non-negative value of an individual Sapling note.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoteValue(u64);

impl NoteValue {
    /// The zero note value.
    pub const ZERO: NoteValue = NoteValue(0);

    /// Returns the raw underlying value.
    pub fn inner(&self) -> u64 {
        self.0
    }

    /// Creates a note value from its raw numeric value.
    ///
    /// This only enforces that the value is an unsigned 64-bit integer. Callers should
    /// enforce any additional constraints on the value's valid range themselves.
    pub fn from_raw(value: u64) -> Self {
        NoteValue(value)
    }

    pub(crate) fn from_bytes(bytes: [u8; 8]) -> Self {
        NoteValue(u64::from_le_bytes(bytes))
    }

    pub(crate) fn to_le_bits(self) -> BitArray<[u8; 8], Lsb0> {
        BitArray::<_, Lsb0>::new(self.0.to_le_bytes())
    }
}

/// The blinding factor for a [`ValueCommitment`].
#[derive(Clone, Debug)]
pub struct ValueCommitTrapdoor(jubjub::Scalar);

impl ValueCommitTrapdoor {
    /// Generates a new value commitment trapdoor.
    ///
    /// This is public for access by `zcash_proofs`.
    pub fn random(rng: impl RngCore) -> Self {
        ValueCommitTrapdoor(jubjub::Scalar::random(rng))
    }

    /// Constructs `ValueCommitTrapdoor` from the byte representation of a scalar.
    ///
    /// Returns a `None` [`CtOption`] if `bytes` is not a canonical representation of a
    /// Jubjub scalar.
    ///
    /// This is a low-level API, requiring a detailed understanding of the
    /// [use of value commitment trapdoors][saplingbalance] in the Zcash protocol
    /// to use correctly and securely. It is intended to be used in combination
    /// with [`ValueCommitment::derive`].
    ///
    /// [saplingbalance]: https://zips.z.cash/protocol/protocol.pdf#saplingbalance
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        jubjub::Scalar::from_repr(bytes).map(ValueCommitTrapdoor)
    }

    /// Returns the inner Jubjub scalar representing this trapdoor.
    ///
    /// This is public for access by `zcash_proofs`.
    pub fn inner(&self) -> jubjub::Scalar {
        self.0
    }
}

/// A commitment to a [`ValueSum`].
///
/// # Consensus rules
///
/// The Zcash Protocol Spec requires Sapling Spend Descriptions and Output Descriptions to
/// not contain a small order `ValueCommitment`. However, the `ValueCommitment` type as
/// specified (and implemented here) may contain a small order point. In practice, it will
/// not occur:
/// - [`ValueCommitment::derive`] will only produce a small order point if both the given
///   [`NoteValue`] and [`ValueCommitTrapdoor`] are zero. However, the only constructor
///   available for `ValueCommitTrapdoor` is [`ValueCommitTrapdoor::random`], which will
///   produce zero with negligible probability (assuming a non-broken PRNG).
/// - [`ValueCommitmentBytes::decompress`] enforces this by definition, and is the only
///   constructor usable with data received over the network.
#[derive(Clone, Debug)]
pub struct ValueCommitment(jubjub::ExtendedPoint);

impl ValueCommitment {
    /// Derives a `ValueCommitment` by $\mathsf{ValueCommit^{Sapling}}$.
    ///
    /// Defined in [Zcash Protocol Spec § 5.4.8.3: Homomorphic Pedersen commitments (Sapling and Orchard)][concretehomomorphiccommit].
    ///
    /// [concretehomomorphiccommit]: https://zips.z.cash/protocol/protocol.pdf#concretehomomorphiccommit
    pub fn derive(value: NoteValue, rcv: ValueCommitTrapdoor) -> Self {
        let cv = (VALUE_COMMITMENT_VALUE_GENERATOR * jubjub::Scalar::from(value.0))
            + (VALUE_COMMITMENT_RANDOMNESS_GENERATOR * rcv.0);

        ValueCommitment(cv.into())
    }

    /// Returns the inner Jubjub point representing this value commitment.
    pub fn as_inner(&self) -> &jubjub::ExtendedPoint {
        &self.0
    }

    /// Serializes this value commitment to its canonical byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// `cv` as held in [`SpendDescription`] / [`OutputDescription`].
///
/// - Point needed only by verification → [`Self::decompress`], which checks the rules
/// - Everything else (txid & sighash digests, PRF^ock, re-serialization) takes bytes
/// - Mirrors [`redjubjub::VerificationKeyBytes`] & [`EphemeralKeyBytes`] for `rk` / `epk`
///
/// [`SpendDescription`]: crate::bundle::SpendDescription
/// [`OutputDescription`]: crate::bundle::OutputDescription
/// [`EphemeralKeyBytes`]: zcash_note_encryption::EphemeralKeyBytes
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValueCommitmentBytes([u8; 32]);

impl From<[u8; 32]> for ValueCommitmentBytes {
    fn from(bytes: [u8; 32]) -> Self {
        ValueCommitmentBytes(bytes)
    }
}

impl From<ValueCommitmentBytes> for [u8; 32] {
    fn from(cv: ValueCommitmentBytes) -> Self {
        cv.0
    }
}

impl From<ValueCommitment> for ValueCommitmentBytes {
    fn from(cv: ValueCommitment) -> Self {
        ValueCommitmentBytes(cv.to_bytes())
    }
}

impl From<&ValueCommitment> for ValueCommitmentBytes {
    fn from(cv: &ValueCommitment) -> Self {
        ValueCommitmentBytes(cv.to_bytes())
    }
}

impl AsRef<[u8; 32]> for ValueCommitmentBytes {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ValueCommitmentBytes {
    /// Returns the byte encoding of this value commitment.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Recovers the point & its affine coords, enforcing the `cv` rules of
    /// [§ 4.4][spenddesc] / [§ 4.5][outputdesc].
    ///
    /// - Sole constructor of a [`ValueCommitment`] from bytes
    /// - Coords fall out of the same sqrt → a verifier never pays for them twice
    ///
    /// # Errors
    ///
    /// [`InvalidPoint`] if non-canonical or of small order.
    ///
    /// [spenddesc]: https://zips.z.cash/protocol/protocol.pdf#spenddesc
    /// [outputdesc]: https://zips.z.cash/protocol/protocol.pdf#outputdesc
    pub fn decompress(&self) -> Result<(ValueCommitment, ValueCommitmentCoords), InvalidPoint> {
        let affine = decompress_not_small_order(&self.0)?;

        Ok((
            ValueCommitment(affine.into()),
            ValueCommitmentCoords {
                u: affine.get_u(),
                v: affine.get_v(),
            },
        ))
    }
}

/// Affine coordinates of a value commitment, as the Spend and Output circuits take them.
#[derive(Clone, Copy, Debug)]
pub struct ValueCommitmentCoords {
    pub(crate) u: bls12_381::Scalar,
    pub(crate) v: bls12_381::Scalar,
}

impl ValueCommitmentCoords {
    /// The `cv.u` public input.
    pub fn u(&self) -> bls12_381::Scalar {
        self.u
    }

    /// The `cv.v` public input.
    pub fn v(&self) -> bls12_381::Scalar {
        self.v
    }
}

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use proptest::prelude::*;

    use super::{NoteValue, ValueCommitTrapdoor, MAX_NOTE_VALUE};

    prop_compose! {
        /// Generate an arbitrary value in the range of valid nonnegative amounts.
        pub fn arb_note_value()(value in 0u64..MAX_NOTE_VALUE) -> NoteValue {
            NoteValue(value)
        }
    }

    prop_compose! {
        /// Generate an arbitrary value in the range of valid positive amounts less than a
        /// specified value.
        pub fn arb_note_value_bounded(max: u64)(value in 0u64..max) -> NoteValue {
            NoteValue(value)
        }
    }

    prop_compose! {
        /// Generate an arbitrary value in the range of valid positive amounts less than a
        /// specified value.
        pub fn arb_positive_note_value(max: u64)(value in 1u64..max) -> NoteValue {
            NoteValue(value)
        }
    }

    prop_compose! {
        /// Generate an arbitrary Jubjub scalar.
        fn arb_scalar()(bytes in prop::array::uniform32(0u8..)) -> jubjub::Scalar {
            // Instead of rejecting out-of-range bytes, let's reduce them.
            let mut buf = [0; 64];
            buf[..32].copy_from_slice(&bytes);
            jubjub::Scalar::from_bytes_wide(&buf)
        }
    }

    prop_compose! {
        /// Generate an arbitrary ValueCommitTrapdoor
        pub fn arb_trapdoor()(rcv in arb_scalar()) -> ValueCommitTrapdoor {
            ValueCommitTrapdoor(rcv)
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{
        testing::{arb_note_value_bounded, arb_trapdoor},
        BalanceError, CommitmentSum, TrapdoorSum, ValueCommitment, ValueSum,
    };

    proptest! {
        #[test]
        fn bsk_consistent_with_bvk(
            values in (1usize..10).prop_flat_map(|n_values| prop::collection::vec(
                (arb_note_value_bounded((i64::MAX as u64) / (n_values as u64)), arb_trapdoor()),
                n_values,
            ))
        ) {
            let value_balance: i64 = values
                .iter()
                .map(|(value, _)| value)
                .sum::<Result<ValueSum, BalanceError>>()
                .expect("we generate values that won't overflow")
                .try_into()
                .unwrap();

            let bsk = values
                .iter()
                .map(|(_, rcv)| rcv)
                .sum::<TrapdoorSum>()
                .into_bsk();

            let bvk = values
                .into_iter()
                .map(|(value, rcv)| ValueCommitment::derive(value, rcv))
                .sum::<CommitmentSum>()
                .into_bvk(value_balance);

            assert_eq!(redjubjub::VerificationKey::from(&bsk), bvk);
        }
    }
}
