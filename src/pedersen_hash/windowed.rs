//! Sapling MerkleCRH over precomputed window tables, backing [`crate::Node`]'s hashing
//!
//! - Fixed [`INPUT_BITS`] message (tables hold only what that length reads, ≈2.8 MiB)
//! - One 7M mixed addition per [`WINDOW_BITS`] input bits, no scalar-field arithmetic
//! - Equals [`pedersen_hash`] on every input (Jubjub addition complete, no exceptional cases)
//! - Projective output, so a batch of hashes shares one inversion
//!
//! [`pedersen_hash`]: super::pedersen_hash

use alloc::{boxed::Box, vec::Vec};
use ff::PrimeField;
use group::Curve;
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint};
use lazy_static::lazy_static;

use crate::constants::{PEDERSEN_HASH_CHUNKS_PER_GENERATOR, PEDERSEN_HASH_GENERATORS};

const PERSONALIZATION_BITS: usize = 6;

/// Low bits of each child read by the hash (bit 255 ignored, canonical or not)
const CHILD_BITS: usize = bls12_381::Scalar::NUM_BITS as usize;

/// Personalization ‖ lhs ‖ rhs
const INPUT_BITS: usize = PERSONALIZATION_BITS + 2 * CHILD_BITS;

/// Input bits per Pedersen hash chunk
const CHUNK_BITS: usize = 3;

const INPUT_CHUNKS: usize = INPUT_BITS.div_ceil(CHUNK_BITS);

/// 512 affine Niels entries per full window (48 KiB)
const WINDOW_CHUNKS: usize = 3;

const WINDOW_BITS: usize = CHUNK_BITS * WINDOW_CHUNKS;

const _: () = assert!(
    PEDERSEN_HASH_CHUNKS_PER_GENERATOR.is_multiple_of(WINDOW_CHUNKS),
    "a window never spans two generators"
);
const _: () = assert!(
    INPUT_CHUNKS <= PEDERSEN_HASH_GENERATORS.len() * PEDERSEN_HASH_CHUNKS_PER_GENERATOR,
    "enough generators for one message"
);

lazy_static! {
    /// One table per window, in input order (last holds [`INPUT_CHUNKS`]'s remainder only)
    static ref WINDOWS: Vec<Box<[AffineNielsPoint]>> = chunk_bases()
        .chunks(WINDOW_CHUNKS)
        .map(sums)
        .collect();
}

/// Each input chunk's base (chunk `i` of a generator = `[2^{4i}]` generator)
fn chunk_bases() -> Vec<ExtendedPoint> {
    PEDERSEN_HASH_GENERATORS
        .iter()
        .flat_map(|generator| {
            let mut next = ExtendedPoint::from(*generator);
            (0..PEDERSEN_HASH_CHUNKS_PER_GENERATOR).map(move |_| {
                let base = next;
                next = next.double().double().double().double();
                base
            })
        })
        .take(INPUT_CHUNKS)
        .collect()
}

/// Entry `i` = Σ_k enc(chunk k of `i`) · `bases[k]`
fn sums(bases: &[ExtendedPoint]) -> Box<[AffineNielsPoint]> {
    let digits: Vec<[ExtendedPoint; 1 << CHUNK_BITS]> = bases.iter().map(encodings).collect();
    let points: Vec<ExtendedPoint> = (0..1usize << (CHUNK_BITS * bases.len()))
        .map(|i| {
            digits
                .iter()
                .enumerate()
                .fold(ExtendedPoint::identity(), |sum, (k, digit)| {
                    sum + digit[(i >> (CHUNK_BITS * k)) & ((1 << CHUNK_BITS) - 1)]
                })
        })
        .collect();
    let mut affine = vec![AffinePoint::identity(); points.len()];
    ExtendedPoint::batch_normalize(&points, &mut affine);
    affine.iter().map(AffinePoint::to_niels).collect()
}

/// `enc(abc) · base` for each chunk value `abc` (a = bit 0): `1 + a + 2b`, negated if `c`
fn encodings(base: &ExtendedPoint) -> [ExtendedPoint; 1 << CHUNK_BITS] {
    let multiples = [
        *base,
        base.double(),
        base.double() + base,
        base.double().double(),
    ];
    core::array::from_fn(|abc| match abc & 4 {
        0 => multiples[abc & 3],
        _ => -multiples[abc & 3],
    })
}

/// `pedersen_hash(MerkleTree(depth), lhs[..CHILD_BITS] ‖ rhs[..CHILD_BITS])`, still projective
///
/// - Panics if `depth` >= 63 (same as [`super::Personalization::MerkleTree`])
pub(crate) fn merkle_hash(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> ExtendedPoint {
    // all-ones = `Personalization::NoteCommitment`
    assert!(depth < (1 << PERSONALIZATION_BITS) - 1);
    let mut words = [0u64; INPUT_BITS.div_ceil(64)];
    words[0] = depth as u64;
    place_child(&mut words, lhs, PERSONALIZATION_BITS);
    place_child(&mut words, rhs, PERSONALIZATION_BITS + CHILD_BITS);

    WINDOWS
        .iter()
        .enumerate()
        .fold(ExtendedPoint::identity(), |hash, (w, table)| {
            hash + table[window_bits(&words, w * WINDOW_BITS) & (table.len() - 1)]
        })
}

/// ORs `child`'s low [`CHILD_BITS`] little-endian bits into `words` from bit `at`
fn place_child(words: &mut [u64], child: &[u8; 32], at: usize) {
    let (limbs, _) = child.as_chunks::<8>();
    for (i, limb) in limbs.iter().enumerate() {
        let limb = u64::from_le_bytes(*limb);
        let limb = match i {
            3 => limb & (u64::MAX >> (256 - CHILD_BITS)),
            _ => limb,
        };
        let (word, shift) = ((at + 64 * i) / 64, (at + 64 * i) % 64);
        words[word] |= limb << shift;
        if shift > 0 {
            words[word + 1] |= limb >> (64 - shift);
        }
    }
}

/// The [`WINDOW_BITS`] bits of `words` from bit `at`
fn window_bits(words: &[u64], at: usize) -> usize {
    let (word, shift) = (at / 64, at % 64);
    let low = words[word] >> shift;
    let high = match shift + WINDOW_BITS > 64 {
        true => words[word + 1] << (64 - shift),
        false => 0,
    };
    ((low | high) & ((1 << WINDOW_BITS) - 1)) as usize
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::mem::size_of;
    use group::Curve;
    use jubjub::{AffineNielsPoint, ExtendedPoint};
    use rand_core::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use super::{merkle_hash, CHILD_BITS, WINDOWS};
    use crate::pedersen_hash::{pedersen_hash, Personalization};

    /// Reference packs bit by bit through the unwindowed hash
    fn reference(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> ExtendedPoint {
        let bits =
            |child: [u8; 32]| (0..CHILD_BITS).map(move |at| (child[at / 8] >> (at % 8)) & 1 == 1);
        pedersen_hash(
            Personalization::MerkleTree(depth),
            bits(*lhs).chain(bits(*rhs)),
        )
        .into()
    }

    #[test]
    fn merkle_hash_equals_pedersen_hash_at_every_depth_and_child_width() {
        let rng = &mut XorShiftRng::from_seed([7; 16]);
        let mut random = [0; 32];
        rng.fill_bytes(&mut random);
        // bls12_381 r − 1, largest canonical node
        let max_canonical: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4,
            0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29,
            0x53, 0xa7, 0xed, 0x73,
        ];
        let children: [(&str, [u8; 32]); 5] = [
            ("zero", [0; 32]),
            ("low byte", [1; 32]),
            ("max canonical", max_canonical),
            ("all ones, bit 255 ignored", [0xff; 32]),
            ("random", random),
        ];

        for depth in 0..63 {
            for (lhs_name, lhs) in &children {
                for (rhs_name, rhs) in &children {
                    assert_eq!(
                        merkle_hash(depth, lhs, rhs).to_affine(),
                        reference(depth, lhs, rhs).to_affine(),
                        "depth {depth}, {lhs_name} ‖ {rhs_name}"
                    );
                }
            }
        }
    }

    #[test]
    fn tables_cover_one_message_in_under_3_mib() {
        let sizes: Vec<usize> = WINDOWS.iter().map(|table| table.len()).collect();
        assert_eq!((sizes.len(), sizes.last()), (58, Some(&8)));
        assert!(sizes[..57].iter().all(|&size| size == 512));

        let bytes = sizes.iter().sum::<usize>() * size_of::<AffineNielsPoint>();
        assert!(bytes < 3 << 20, "{bytes} bytes");
    }

    #[test]
    #[should_panic]
    fn merkle_hash_refuses_the_note_commitment_personalization() {
        merkle_hash(63, &[0; 32], &[0; 32]);
    }
}
