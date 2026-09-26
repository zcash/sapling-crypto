//! Sapling key components.
//!
//! Implements [section 4.2.2] of the Zcash Protocol Specification.
//!
//! [section 4.2.2]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents

use alloc::vec::Vec;
use core::fmt;
use corez::io::{self, Read, Write};

use super::{
    address::PaymentAddress,
    constants::{self, PROOF_GENERATION_KEY_GENERATOR},
    note_encryption::KDF_SAPLING_PERSONALIZATION,
    spec::{
        crh_ivk, diversify_hash, ka_sapling_agree, ka_sapling_agree_prepared,
        ka_sapling_derive_public, ka_sapling_derive_public_subgroup_prepared, PreparedBase,
        PreparedBaseSubgroup, PreparedScalar,
    },
};

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use ff::{Field, PrimeField};
use group::{Curve, Group, GroupEncoding};
use redjubjub::SpendAuth;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zcash_note_encryption::EphemeralKeyBytes;
use zcash_spec::PrfExpand;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::zeroize_secret;

#[cfg(all(feature = "circuit", test))]
use rand_core::Rng;

/// Errors that can occur in the decoding of Sapling spending keys.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodingError {
    /// The length of the byte slice provided for decoding was incorrect.
    LengthInvalid { expected: usize, actual: usize },
    /// Could not decode the `ask` bytes to a jubjub field element.
    InvalidAsk,
    /// Could not decode the `nsk` bytes to a jubjub field element.
    InvalidNsk,
    /// The incoming viewing key derived from the decoded key is zero.
    InvalidIvk,
    /// An extended spending key had an unsupported child index: either a non-hardened
    /// index, or a non-zero index at depth 0.
    UnsupportedChildIndex,
}

impl fmt::Display for DecodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodingError::LengthInvalid { expected, actual } => {
                write!(f, "invalid slice length (expected {expected}, got {actual}")
            }
            DecodingError::InvalidAsk => write!(f, "invalid `ask`"),
            DecodingError::InvalidNsk => write!(f, "invalid `nsk`"),
            DecodingError::InvalidIvk => write!(f, "derived `ivk` is zero"),
            DecodingError::UnsupportedChildIndex => write!(
                f,
                "unsupported child index (either non-hardened, or non-zero at depth 0)"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodingError {}

/// A spend authorizing key, used to create spend authorization signatures.
///
/// $\mathsf{ask}$ as defined in [Zcash Protocol Spec § 4.2.2: Sapling Key Components][saplingkeycomponents].
///
/// If the `zeroize` feature is enabled, the key material is zeroized on drop.
///
/// [saplingkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents
#[derive(Clone, Debug)]
pub struct SpendAuthorizingKey(redjubjub::SigningKey<SpendAuth>);

impl PartialEq for SpendAuthorizingKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes().ct_eq(&other.0.to_bytes()).into()
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for SpendAuthorizingKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// The inner `redjubjub::SigningKey` zeroizes itself on drop.
#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for SpendAuthorizingKey {}

impl Eq for SpendAuthorizingKey {}

impl From<&SpendValidatingKey> for jubjub::ExtendedPoint {
    fn from(spend_validating_key: &SpendValidatingKey) -> jubjub::ExtendedPoint {
        jubjub::ExtendedPoint::from_bytes(&spend_validating_key.to_bytes()).unwrap()
    }
}

impl SpendAuthorizingKey {
    /// Derives ask from sk. Internal use only, does not enforce all constraints.
    fn derive_inner(sk: &[u8]) -> jubjub::Scalar {
        let mut prf = PrfExpand::SAPLING_ASK.with(sk);
        let ask = jubjub::Scalar::from_bytes_wide(&prf);
        zeroize_secret(&mut prf);
        ask
    }

    /// Constructs a `SpendAuthorizingKey` from a raw scalar.
    ///
    /// The scalar is copied into the returned key; the caller is responsible for
    /// zeroizing its own copy once it is no longer needed.
    pub(crate) fn from_scalar(ask: jubjub::Scalar) -> Option<Self> {
        if ask.is_zero().into() {
            None
        } else {
            let mut repr = ask.to_bytes();
            let key = SpendAuthorizingKey(
                redjubjub::SigningKey::from_bytes(&repr)
                    .expect("canonical scalar encodings are valid RedJubjub signing keys"),
            );
            zeroize_secret(&mut repr);
            Some(key)
        }
    }

    /// Derives a `SpendAuthorizingKey` from a spending key.
    fn from_spending_key(sk: &[u8]) -> Option<Self> {
        Self::from_scalar(Self::derive_inner(sk))
    }

    /// Parses a `SpendAuthorizingKey` from its encoded form.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes)
            .ok()
            .and_then(|b| {
                // RedJubjub.Private permits the full set of Jubjub scalars including
                // zero. However, a SpendAuthorizingKey is further restricted within the
                // Sapling key tree to be a non-zero scalar.
                jubjub::Scalar::from_repr(b)
                    .and_then(|s| {
                        CtOption::new(
                            redjubjub::SigningKey::from_bytes(&b)
                                .expect("RedJubjub permits the set of valid SpendAuthorizingKeys"),
                            !s.is_zero(),
                        )
                    })
                    .into()
            })
            .map(SpendAuthorizingKey)
    }

    /// Converts this spend authorizing key to its serialized form.
    ///
    /// The returned array is secret key material; the caller is responsible for
    /// zeroizing it once it is no longer needed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Converts this spend authorizing key to a raw scalar.
    ///
    /// Only used for ZIP 32 child derivation.
    pub(crate) fn to_scalar(&self) -> jubjub::Scalar {
        let mut repr = self.0.to_bytes();
        let ask = jubjub::Scalar::from_repr(repr).unwrap();
        zeroize_secret(&mut repr);
        ask
    }

    /// Randomizes this spend authorizing key with the given `randomizer`.
    ///
    /// The resulting key can be used to actually sign a spend.
    pub fn randomize(&self, randomizer: &jubjub::Scalar) -> redjubjub::SigningKey<SpendAuth> {
        self.0.randomize(randomizer)
    }
}

/// A key used to validate spend authorization signatures.
///
/// Defined in [Zcash Protocol Spec § 4.2.2: Sapling Key Components][saplingkeycomponents].
///
/// [saplingkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents
#[derive(Clone, Debug)]
pub struct SpendValidatingKey(redjubjub::VerificationKey<SpendAuth>);

impl From<&SpendAuthorizingKey> for SpendValidatingKey {
    fn from(ask: &SpendAuthorizingKey) -> Self {
        SpendValidatingKey((&ask.0).into())
    }
}

impl PartialEq for SpendValidatingKey {
    fn eq(&self, other: &Self) -> bool {
        <[u8; 32]>::from(self.0)
            .ct_eq(&<[u8; 32]>::from(other.0))
            .into()
    }
}

impl Eq for SpendValidatingKey {}

impl SpendValidatingKey {
    /// For circuit tests only.
    #[cfg(all(feature = "circuit", test))]
    pub(crate) fn fake_random<R: Rng>(mut rng: R) -> Self {
        loop {
            if let Some(k) = Self::from_bytes(&jubjub::SubgroupPoint::random(&mut rng).to_bytes()) {
                break k;
            }
        }
    }

    /// Only exposed for `zcashd` unit tests.
    #[cfg(feature = "temporary-zcashd")]
    pub fn temporary_zcash_from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes)
    }

    /// Parses a `SpendValidatingKey` from its encoded form.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes)
            .ok()
            .and_then(|b| {
                // RedJubjub.Public permits the full set of Jubjub points including the
                // identity and cofactors; this is the type used for `rk` in Spend
                // descriptions. However, a SpendValidatingKey is further restricted
                // within the Sapling key tree to be a non-identity element of the
                // prime-order subgroup.
                jubjub::SubgroupPoint::from_bytes(&b)
                    .and_then(|p| {
                        CtOption::new(
                            redjubjub::VerificationKey::try_from(b)
                                .expect("RedJubjub permits the set of valid SpendValidatingKeys"),
                            !p.is_identity(),
                        )
                    })
                    .into()
            })
            .map(SpendValidatingKey)
    }

    /// Converts this spend validating key to its serialized form,
    /// `LEBS2OSP_256(repr_J(ak))`.
    pub fn to_bytes(&self) -> [u8; 32] {
        <[u8; 32]>::from(self.0)
    }

    /// Randomizes this spend validating key with the given `randomizer`.
    pub fn randomize(&self, randomizer: &jubjub::Scalar) -> redjubjub::VerificationKey<SpendAuth> {
        self.0.randomize(randomizer)
    }
}

/// An outgoing viewing key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutgoingViewingKey(pub [u8; 32]);

/// `OutgoingViewingKey` is `Copy`, so it cannot implement `ZeroizeOnDrop`; types that
/// own one alongside secret key material are responsible for zeroizing it.
#[cfg(feature = "zeroize")]
impl Zeroize for OutgoingViewingKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// A Sapling expanded spending key
///
/// If the `zeroize` feature is enabled, the key material is zeroized on drop.
#[derive(Clone)]
pub struct ExpandedSpendingKey {
    pub ask: SpendAuthorizingKey,
    pub nsk: jubjub::Fr,
    pub ovk: OutgoingViewingKey,
}

#[cfg(feature = "zeroize")]
impl Zeroize for ExpandedSpendingKey {
    fn zeroize(&mut self) {
        self.ask.zeroize();
        self.nsk.zeroize();
        self.ovk.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for ExpandedSpendingKey {}

#[cfg(feature = "zeroize")]
impl Drop for ExpandedSpendingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for ExpandedSpendingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandedSpendingKey")
            .finish_non_exhaustive()
    }
}

impl ExpandedSpendingKey {
    /// Expands a spending key into its components.
    ///
    /// # Panics
    ///
    /// Panics if this spending key expands to `ask = 0`. This has a negligible
    /// probability of occurring.
    pub fn from_spending_key(sk: &[u8]) -> Self {
        let ask =
            SpendAuthorizingKey::from_spending_key(sk).expect("negligible chance of ask == 0");
        let mut nsk_prf = PrfExpand::SAPLING_NSK.with(sk);
        let nsk = jubjub::Fr::from_bytes_wide(&nsk_prf);
        zeroize_secret(&mut nsk_prf);
        let mut ovk_prf = PrfExpand::SAPLING_OVK.with(sk);
        let mut ovk = OutgoingViewingKey([0u8; 32]);
        ovk.0.copy_from_slice(&ovk_prf[..32]);
        zeroize_secret(&mut ovk_prf);
        ExpandedSpendingKey { ask, nsk, ovk }
    }

    pub fn proof_generation_key(&self) -> ProofGenerationKey {
        ProofGenerationKey {
            ak: (&self.ask).into(),
            nsk: self.nsk,
        }
    }

    /// Decodes the expanded spending key from its serialized representation
    /// as part of the encoding of the extended spending key as defined in
    /// [ZIP 32](https://zips.z.cash/zip-0032)
    ///
    /// Returns an error if the incoming viewing key derived from the key is zero.
    pub fn from_bytes(b: &[u8]) -> Result<Self, DecodingError> {
        if b.len() != 96 {
            return Err(DecodingError::LengthInvalid {
                expected: 96,
                actual: b.len(),
            });
        }

        let ask = SpendAuthorizingKey::from_bytes(&b[0..32]).ok_or(DecodingError::InvalidAsk)?;
        let nsk = Option::from(jubjub::Fr::from_repr(b[32..64].try_into().unwrap()))
            .ok_or(DecodingError::InvalidNsk)?;
        let ovk = OutgoingViewingKey(b[64..96].try_into().unwrap());

        let expsk = ExpandedSpendingKey { ask, nsk, ovk };
        expsk
            .proof_generation_key()
            .to_viewing_key()
            .map(|_| expsk)
            .ok_or(DecodingError::InvalidIvk)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = [0u8; 96];
        reader.read_exact(repr.as_mut())?;
        let result = Self::from_bytes(&repr);
        zeroize_secret(&mut repr);
        result.map_err(|e| match e {
            DecodingError::InvalidAsk => {
                io::Error::new(io::ErrorKind::InvalidData, "ask not in field")
            }
            DecodingError::InvalidNsk => {
                io::Error::new(io::ErrorKind::InvalidData, "nsk not in field")
            }
            DecodingError::InvalidIvk => io::Error::new(io::ErrorKind::InvalidData, "ivk is zero"),
            DecodingError::LengthInvalid { .. } | DecodingError::UnsupportedChildIndex => {
                unreachable!()
            }
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }

    /// Encodes the expanded spending key to its serialized representation
    /// as part of the encoding of the extended spending key as defined in
    /// [ZIP 32](https://zips.z.cash/zip-0032)
    ///
    /// The returned array is secret key material; the caller is responsible for
    /// zeroizing it once it is no longer needed.
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        result[0..32].copy_from_slice(&self.ask.to_bytes());
        result[32..64].copy_from_slice(&self.nsk.to_repr());
        result[64..96].copy_from_slice(&self.ovk.0);
        result
    }
}

/// A Sapling proof generation key.
///
/// If the `zeroize` feature is enabled, `nsk` is zeroized on drop.
#[derive(Clone)]
pub struct ProofGenerationKey {
    pub ak: SpendValidatingKey,
    pub nsk: jubjub::Fr,
}

#[cfg(feature = "zeroize")]
impl Zeroize for ProofGenerationKey {
    fn zeroize(&mut self) {
        // `ak` is public and is left intact.
        self.nsk.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for ProofGenerationKey {}

#[cfg(feature = "zeroize")]
impl Drop for ProofGenerationKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for ProofGenerationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofGenerationKey")
            .field("ak", &self.ak)
            .finish_non_exhaustive()
    }
}

impl ProofGenerationKey {
    /// Derives the viewing key corresponding to this proof generation key.
    ///
    /// Returns `None` if the derived incoming viewing key is zero. Such a key is invalid
    /// and has no payment addresses.
    pub fn to_viewing_key(&self) -> Option<ViewingKey> {
        ViewingKey::from_parts(
            self.ak.clone(),
            NullifierDerivingKey(constants::PROOF_GENERATION_KEY_GENERATOR * self.nsk),
        )
    }
}

/// A key used to derive the nullifier for a Sapling note.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NullifierDerivingKey(pub jubjub::SubgroupPoint);

/// A Sapling viewing key: the spend validating key `ak` and the nullifier deriving key
/// `nk`.
///
/// The incoming viewing key derived from a `ViewingKey` is never zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewingKey {
    ak: SpendValidatingKey,
    nk: NullifierDerivingKey,
}

impl ViewingKey {
    /// Constructs a viewing key from its components.
    ///
    /// Returns `None` if the incoming viewing key derived from `ak` and `nk` is zero.
    /// Such a key is invalid and has no payment addresses.
    pub fn from_parts(ak: SpendValidatingKey, nk: NullifierDerivingKey) -> Option<Self> {
        let ivk = crh_ivk(ak.to_bytes(), nk.0.to_bytes());
        SaplingIvk::from_scalar(ivk)
            .into_option()
            .map(|_| ViewingKey { ak, nk })
    }

    /// Returns the spend validating key.
    pub fn ak(&self) -> &SpendValidatingKey {
        &self.ak
    }

    /// Returns the nullifier deriving key.
    pub fn nk(&self) -> &NullifierDerivingKey {
        &self.nk
    }

    pub fn rk(&self, ar: jubjub::Fr) -> redjubjub::VerificationKey<SpendAuth> {
        self.ak.randomize(&ar)
    }

    /// Derives the incoming viewing key.
    pub fn ivk(&self) -> SaplingIvk {
        SaplingIvk::from_scalar(crh_ivk(self.ak.to_bytes(), self.nk.0.to_bytes()))
            .expect("ViewingKey::from_parts rejects a zero ivk")
    }

    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        self.ivk().to_payment_address(diversifier)
    }
}

/// A Sapling key that provides the capability to view incoming and outgoing transactions.
#[derive(Debug, PartialEq, Eq)]
pub struct FullViewingKey {
    pub vk: ViewingKey,
    pub ovk: OutgoingViewingKey,
}

impl Clone for FullViewingKey {
    fn clone(&self) -> Self {
        FullViewingKey {
            vk: self.vk.clone(),
            ovk: self.ovk,
        }
    }
}

impl FullViewingKey {
    /// Derives the full viewing key corresponding to an expanded spending key.
    ///
    /// Returns `None` if the derived incoming viewing key is zero. Such a key is invalid
    /// and has no payment addresses.
    pub fn from_expanded_spending_key(expsk: &ExpandedSpendingKey) -> Option<Self> {
        ViewingKey::from_parts(
            (&expsk.ask).into(),
            NullifierDerivingKey(PROOF_GENERATION_KEY_GENERATOR * expsk.nsk),
        )
        .map(|vk| FullViewingKey { vk, ovk: expsk.ovk })
    }

    /// Reads a full viewing key from its raw encoding.
    ///
    /// Returns an error if `ak` is not a prime-order point, if `nk` is not in the
    /// prime-order subgroup, or if the derived incoming viewing key is zero.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let ak = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            SpendValidatingKey::from_bytes(&buf)
        };
        let nk = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf)
        };
        if ak.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ak not of prime order",
            ));
        }
        if nk.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nk not in prime-order subgroup",
            ));
        }
        let ak = ak.unwrap();
        let nk = NullifierDerivingKey(nk.unwrap());
        let vk = ViewingKey::from_parts(ak, nk)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ivk is zero"))?;

        let mut ovk = [0u8; 32];
        reader.read_exact(&mut ovk)?;

        Ok(FullViewingKey {
            vk,
            ovk: OutgoingViewingKey(ovk),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.vk.ak().to_bytes())?;
        writer.write_all(&self.vk.nk().0.to_bytes())?;
        writer.write_all(&self.ovk.0)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        self.write(&mut result[..])
            .expect("should be able to serialize a FullViewingKey");
        result
    }
}

/// A Sapling incoming viewing key.
///
/// Defined in [Zcash Protocol Spec § 4.2.2: Sapling Key Components][saplingkeycomponents]
/// as an integer in the range $\{1 .. 2^{\ell_{\mathsf{ivk}}} - 1\}$, where
/// $\ell_{\mathsf{ivk}} = 251$.
///
/// [saplingkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaplingIvk(jubjub::Fr);

impl SaplingIvk {
    /// Parses an incoming viewing key from its little-endian encoding.
    ///
    /// Returns `None` if `bytes` does not encode an integer in the range
    /// $\{1 .. 2^{251} - 1\}$.
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        Self::parse_with(bytes, |ivk| ivk)
    }

    /// Parses an incoming viewing key from its little-endian encoding, and passes it to
    /// `f`.
    ///
    /// Returns `None` if `bytes` does not encode an integer in the range
    /// $\{1 .. 2^{251} - 1\}$. Validity is determined in constant time.
    pub(crate) fn parse_with<T>(bytes: &[u8; 32], f: impl FnOnce(Self) -> T) -> CtOption<T> {
        // An encoding with any of the five most significant bits set is at least 2^251.
        let in_range = (bytes[31] & 0b1111_1000).ct_eq(&0);
        jubjub::Fr::from_repr(*bytes)
            .and_then(|ivk| CtOption::new(f(SaplingIvk(ivk)), in_range & !ivk.is_zero()))
    }

    /// Samples a uniformly random incoming viewing key.
    pub(crate) fn random<R: rand_core::Rng + ?Sized>(rng: &mut R) -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes[31] &= 0b0000_0111;
            if let Some(ivk) = Self::from_bytes(&bytes).into_option() {
                break ivk;
            }
        }
    }

    /// Constructs an incoming viewing key from a scalar.
    ///
    /// Returns `None` if `ivk` is not in the range $\{1 .. 2^{251} - 1\}$.
    pub(crate) fn from_scalar(ivk: jubjub::Fr) -> CtOption<Self> {
        Self::from_bytes(&ivk.to_repr())
    }

    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        let prepared_ivk = PreparedIncomingViewingKey::new(self);
        DiversifiedTransmissionKey::derive(&prepared_ivk, &diversifier)
            .and_then(|pk_d| PaymentAddress::from_parts(diversifier, pk_d))
    }

    pub fn to_repr(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

/// A Sapling incoming viewing key that has been precomputed for trial decryption.
#[derive(Clone, Debug)]
pub struct PreparedIncomingViewingKey(PreparedScalar);

#[cfg(feature = "std")]
impl memuse::DynamicUsage for PreparedIncomingViewingKey {
    fn dynamic_usage(&self) -> usize {
        self.0.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.0.dynamic_usage_bounds()
    }
}

impl PreparedIncomingViewingKey {
    /// Performs the necessary precomputations to use a `SaplingIvk` for note decryption.
    pub fn new(ivk: &SaplingIvk) -> Self {
        Self(PreparedScalar::new(&ivk.0))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    pub fn g_d(&self) -> Option<jubjub::SubgroupPoint> {
        diversify_hash(&self.0)
    }
}

/// The diversified transmission key for a given payment address.
///
/// Defined in [Zcash Protocol Spec § 4.2.2: Sapling Key Components][saplingkeycomponents].
///
/// The protocol requires this key to not be the identity. [`PaymentAddress::from_parts`]
/// enforces this.
///
/// [saplingkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiversifiedTransmissionKey(jubjub::SubgroupPoint);

impl DiversifiedTransmissionKey {
    /// Defined in [Zcash Protocol Spec § 4.2.2: Sapling Key Components][saplingkeycomponents].
    ///
    /// Returns `None` if `d` is an invalid diversifier.
    ///
    /// [saplingkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents
    pub(crate) fn derive(ivk: &PreparedIncomingViewingKey, d: &Diversifier) -> Option<Self> {
        d.g_d()
            .map(PreparedBaseSubgroup::new)
            .map(|g_d| ka_sapling_derive_public_subgroup_prepared(&ivk.0, &g_d))
            .map(DiversifiedTransmissionKey)
    }

    /// $abst_J(bytes)$
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        jubjub::SubgroupPoint::from_bytes(bytes).map(DiversifiedTransmissionKey)
    }

    /// $repr_J(self)$
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Returns true if this is the identity.
    pub(crate) fn is_identity(&self) -> bool {
        self.0.is_identity().into()
    }

    /// Exposes the inner Jubjub point.
    ///
    /// This API is exposed for `zcash_proof` usage, and will be removed when this type is
    /// refactored into the `sapling-crypto` crate.
    pub fn inner(&self) -> jubjub::SubgroupPoint {
        self.0
    }
}

impl ConditionallySelectable for DiversifiedTransmissionKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        DiversifiedTransmissionKey(jubjub::SubgroupPoint::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

/// An ephemeral secret key used to encrypt an output note on-chain.
///
/// `esk` is "ephemeral" in the sense that each secret key is only used once. In
/// practice, `esk` is derived deterministically from the note that it is encrypting.
///
/// $\mathsf{KA}^\mathsf{Sapling}.\mathsf{Private} := \mathbb{F}_{r_J}$
///
/// Defined in [section 5.4.5.3: Sapling Key Agreement][concretesaplingkeyagreement].
///
/// [concretesaplingkeyagreement]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement
#[derive(Debug)]
pub struct EphemeralSecretKey(pub(crate) jubjub::Scalar);

impl ConstantTimeEq for EphemeralSecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl EphemeralSecretKey {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        jubjub::Scalar::from_bytes(bytes).map(EphemeralSecretKey)
    }

    pub(crate) fn derive_public(&self, g_d: jubjub::ExtendedPoint) -> EphemeralPublicKey {
        EphemeralPublicKey(ka_sapling_derive_public(&self.0, &g_d))
    }

    pub(crate) fn agree(&self, pk_d: &DiversifiedTransmissionKey) -> SharedSecret {
        SharedSecret(ka_sapling_agree(&self.0, &pk_d.0.into()))
    }
}

/// An ephemeral public key used to encrypt an output note on-chain.
///
/// `epk` is "ephemeral" in the sense that each public key is only used once. In practice,
/// `epk` is derived deterministically from the note that it is encrypting.
///
/// $\mathsf{KA}^\mathsf{Sapling}.\mathsf{Public} := \mathbb{J}$
///
/// Defined in [section 5.4.5.3: Sapling Key Agreement][concretesaplingkeyagreement].
///
/// [concretesaplingkeyagreement]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement
#[derive(Debug)]
pub struct EphemeralPublicKey(jubjub::ExtendedPoint);

impl EphemeralPublicKey {
    pub(crate) fn from_affine(epk: jubjub::AffinePoint) -> Self {
        EphemeralPublicKey(epk.into())
    }

    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        jubjub::ExtendedPoint::from_bytes(bytes).map(EphemeralPublicKey)
    }

    pub(crate) fn to_bytes(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.0.to_bytes())
    }
}

/// A Sapling ephemeral public key that has been precomputed for trial decryption.
#[derive(Clone, Debug)]
pub struct PreparedEphemeralPublicKey(PreparedBase);

impl PreparedEphemeralPublicKey {
    pub(crate) fn new(epk: EphemeralPublicKey) -> Self {
        PreparedEphemeralPublicKey(PreparedBase::new(epk.0))
    }

    pub(crate) fn agree(&self, ivk: &PreparedIncomingViewingKey) -> SharedSecret {
        SharedSecret(ka_sapling_agree_prepared(&ivk.0, &self.0))
    }
}

/// $\mathsf{KA}^\mathsf{Sapling}.\mathsf{SharedSecret} := \mathbb{J}^{(r)}$
///
/// Defined in [section 5.4.5.3: Sapling Key Agreement][concretesaplingkeyagreement].
///
/// [concretesaplingkeyagreement]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement
#[derive(Debug)]
pub struct SharedSecret(jubjub::SubgroupPoint);

impl SharedSecret {
    /// For checking test vectors only.
    #[cfg(test)]
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Only for use in batched note encryption.
    pub(crate) fn batch_to_affine(
        shared_secrets: Vec<Option<Self>>,
    ) -> impl Iterator<Item = Option<jubjub::AffinePoint>> {
        // Filter out the positions for which ephemeral_key was not a valid encoding.
        let secrets: Vec<_> = shared_secrets
            .iter()
            .filter_map(|s| s.as_ref().map(|s| jubjub::ExtendedPoint::from(s.0)))
            .collect();

        // Batch-normalize the shared secrets.
        let mut secrets_affine = vec![jubjub::AffinePoint::identity(); secrets.len()];
        group::Curve::batch_normalize(&secrets, &mut secrets_affine);

        // Re-insert the invalid ephemeral_key positions.
        let mut secrets_affine = secrets_affine.into_iter();
        shared_secrets
            .into_iter()
            .map(move |s| s.and_then(|_| secrets_affine.next()))
    }

    /// Defined in [Zcash Protocol Spec § 5.4.5.4: Sapling Key Agreement][concretesaplingkdf].
    ///
    /// [concretesaplingkdf]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkdf
    pub(crate) fn kdf_sapling(self, ephemeral_key: &EphemeralKeyBytes) -> Blake2bHash {
        Self::kdf_sapling_inner(
            jubjub::ExtendedPoint::from(self.0).to_affine(),
            ephemeral_key,
        )
    }

    /// Only for direct use in batched note encryption.
    pub(crate) fn kdf_sapling_inner(
        secret: jubjub::AffinePoint,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> Blake2bHash {
        Blake2bParams::new()
            .hash_length(32)
            .personal(KDF_SAPLING_PERSONALIZATION)
            .to_state()
            .update(&secret.to_bytes())
            .update(ephemeral_key.as_ref())
            .finalize()
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::{ExpandedSpendingKey, FullViewingKey, SaplingIvk};

    prop_compose! {
        pub fn arb_expanded_spending_key()(v in vec(any::<u8>(), 32..252)) -> ExpandedSpendingKey {
            ExpandedSpendingKey::from_spending_key(&v)
        }
    }

    prop_compose! {
        pub fn arb_full_viewing_key()(sk in arb_expanded_spending_key()) -> FullViewingKey {
            FullViewingKey::from_expanded_spending_key(&sk)
                .expect("negligible chance of ivk == 0")
        }
    }

    prop_compose! {
        pub fn arb_incoming_viewing_key()(fvk in arb_full_viewing_key()) -> SaplingIvk {
            fvk.vk.ivk()
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use group::{Group, GroupEncoding};

    use ff::PrimeField;
    use proptest::prelude::*;

    use super::{
        testing::arb_incoming_viewing_key, FullViewingKey, SaplingIvk, SpendAuthorizingKey,
        SpendValidatingKey,
    };
    use crate::{constants::SPENDING_KEY_GENERATOR, test_vectors};

    #[test]
    fn ak_must_be_prime_order() {
        let mut buf = [0; 96];
        let identity = jubjub::SubgroupPoint::identity();

        // Set both ak and nk to the identity.
        buf[0..32].copy_from_slice(&identity.to_bytes());
        buf[32..64].copy_from_slice(&identity.to_bytes());

        // ak is not allowed to be the identity.
        assert_eq!(
            FullViewingKey::read(&buf[..]).unwrap_err().to_string(),
            "ak not of prime order"
        );

        // Set ak to a basepoint.
        let basepoint = SPENDING_KEY_GENERATOR;
        buf[0..32].copy_from_slice(&basepoint.to_bytes());

        // nk is allowed to be the identity.
        assert!(FullViewingKey::read(&buf[..]).is_ok());
    }

    #[test]
    fn spend_auth_sig_test_vectors() {
        for tv in test_vectors::signatures::make_test_vectors() {
            let sk = SpendAuthorizingKey::from_bytes(&tv.sk).unwrap();
            let vk = SpendValidatingKey::from_bytes(&tv.vk).unwrap();
            let rvk = redjubjub::VerificationKey::try_from(tv.rvk).unwrap();
            let sig = redjubjub::Signature::from(tv.sig);
            let rsig = redjubjub::Signature::from(tv.rsig);

            let alpha = jubjub::Scalar::from_bytes(&tv.alpha).unwrap();

            assert_eq!(sk.randomize(&alpha).to_bytes(), tv.rsk);
            assert_eq!(vk.randomize(&alpha), rvk);

            // assert_eq!(vk.0.verify(&tv.m, &sig), Ok(()));
            // assert_eq!(rvk.verify(&tv.m, &rsig), Ok(()));
            assert_eq!(
                vk.0.verify(&tv.m, &rsig),
                Err(redjubjub::Error::InvalidSignature),
            );
            assert_eq!(
                rvk.verify(&tv.m, &sig),
                Err(redjubjub::Error::InvalidSignature),
            );
        }
    }

    #[test]
    fn ivk_encoding_must_be_in_range() {
        let parses = |bytes: [u8; 32]| bool::from(SaplingIvk::from_bytes(&bytes).is_some());

        // The range is {1 .. 2^251 - 1}.
        assert!(!parses([0; 32]));

        let mut one = [0; 32];
        one[0] = 1;
        assert!(parses(one));

        let mut max = [0xff; 32];
        max[31] = 0b0000_0111;
        assert!(parses(max));

        // 2^251 and r - 1 are canonical scalars, but are not in range.
        let mut two_pow_251 = [0; 32];
        two_pow_251[31] = 0b0000_1000;
        assert!(!parses(two_pow_251));
        assert!(!parses((-jubjub::Fr::one()).to_repr()));
    }

    proptest! {
        #[test]
        fn ivk_encoding_round_trip(ivk in arb_incoming_viewing_key()) {
            prop_assert_eq!(SaplingIvk::from_bytes(&ivk.to_repr()).into_option(), Some(ivk));
        }
    }
}

#[cfg(all(test, feature = "zeroize"))]
mod zeroize_tests {
    use zeroize::Zeroize;

    use super::ExpandedSpendingKey;

    #[test]
    fn expanded_spending_key_zeroizes() {
        let mut expsk = ExpandedSpendingKey::from_spending_key(&[7; 32]);
        assert_ne!(expsk.to_bytes(), [0; 96]);

        expsk.zeroize();
        assert_eq!(expsk.to_bytes(), [0; 96]);
    }

    #[test]
    fn proof_generation_key_zeroizes() {
        let expsk = ExpandedSpendingKey::from_spending_key(&[7; 32]);
        let mut pgk = expsk.proof_generation_key();
        assert_ne!(pgk.nsk, <jubjub::Fr as ff::Field>::ZERO);

        pgk.zeroize();
        assert_eq!(pgk.nsk, <jubjub::Fr as ff::Field>::ZERO);
    }

    #[test]
    fn spend_authorizing_key_zeroizes() {
        let expsk = ExpandedSpendingKey::from_spending_key(&[7; 32]);
        let mut ask = expsk.ask.clone();
        assert_ne!(ask.to_bytes(), [0; 32]);

        ask.zeroize();
        assert_eq!(ask.to_bytes(), [0; 32]);
    }
}
