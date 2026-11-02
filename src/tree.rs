use group::{ff::PrimeField, Curve};
use incrementalmerkletree::{Hashable, Level};
use lazy_static::lazy_static;
use subtle::CtOption;

use alloc::vec::Vec;
use core::fmt;

use super::note::ExtractedNoteCommitment;
#[cfg(feature = "runtime-precomputation")]
use super::pedersen_hash::windowed;
#[cfg(not(feature = "runtime-precomputation"))]
use {
    super::pedersen_hash::{pedersen_hash, Personalization},
    bitvec::{order::Lsb0, view::AsBits},
};

pub const NOTE_COMMITMENT_TREE_DEPTH: u8 = 32;
pub type CommitmentTree =
    incrementalmerkletree::frontier::CommitmentTree<Node, NOTE_COMMITMENT_TREE_DEPTH>;
pub type IncrementalWitness =
    incrementalmerkletree::witness::IncrementalWitness<Node, NOTE_COMMITMENT_TREE_DEPTH>;
pub type MerklePath = incrementalmerkletree::MerklePath<Node, NOTE_COMMITMENT_TREE_DEPTH>;

lazy_static! {
    static ref UNCOMMITTED_SAPLING: bls12_381::Scalar = bls12_381::Scalar::one();
    static ref EMPTY_ROOTS: Vec<Node> = empty_roots();
}

fn empty_roots() -> Vec<Node> {
    let mut v = vec![Node::empty_leaf()];
    for d in 0..NOTE_COMMITMENT_TREE_DEPTH {
        let next = Node::combine(d.into(), &v[usize::from(d)], &v[usize::from(d)]);
        v.push(next);
    }
    v
}

/// Compute a parent node in the Sapling commitment tree given its two children.
pub fn merkle_hash(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    merkle_hash_point(depth, lhs, rhs)
        .to_affine()
        .get_u()
        .to_repr()
}

/// MerkleCRH^Sapling over each child's low 255 bits, still projective (callers normalize)
fn merkle_hash_point(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> jubjub::ExtendedPoint {
    #[cfg(feature = "runtime-precomputation")]
    {
        windowed::merkle_hash(depth, lhs, rhs)
    }
    #[cfg(not(feature = "runtime-precomputation"))]
    {
        fn bits(child: &[u8; 32]) -> impl Iterator<Item = bool> + '_ {
            let child = child.as_bits::<Lsb0>();
            (0..bls12_381::Scalar::NUM_BITS as usize).map(move |i| child[i])
        }
        pedersen_hash(
            Personalization::MerkleTree(depth),
            bits(lhs).chain(bits(rhs)),
        )
        .into()
    }
}

/// The root of a Sapling commitment tree.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct Anchor(jubjub::Base);

impl From<jubjub::Base> for Anchor {
    fn from(anchor_field: jubjub::Base) -> Anchor {
        Anchor(anchor_field)
    }
}

impl From<Node> for Anchor {
    fn from(anchor: Node) -> Anchor {
        Anchor(anchor.0)
    }
}

impl Anchor {
    /// The anchor of the empty Sapling note commitment tree.
    ///
    /// This anchor does not correspond to any valid anchor for a spend, so it
    /// may only be used for coinbase bundles or in circumstances where Sapling
    /// functionality is not active.
    pub fn empty_tree() -> Anchor {
        Anchor(Node::empty_root(NOTE_COMMITMENT_TREE_DEPTH.into()).0)
    }

    pub(crate) fn inner(&self) -> jubjub::Base {
        self.0
    }

    /// Parses a Sapling anchor from a byte encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Anchor> {
        jubjub::Base::from_repr(bytes).map(Self)
    }

    /// Returns the byte encoding of this anchor.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

/// A node within the Sapling commitment tree.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Node(jubjub::Base);

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("repr", &hex::encode(self.0.to_bytes()))
            .finish()
    }
}

impl Node {
    /// Creates a tree leaf from the given Sapling note commitment.
    pub fn from_cmu(value: &ExtractedNoteCommitment) -> Self {
        Node(value.inner())
    }

    /// Constructs a new note commitment tree node from a [`bls12_381::Scalar`]
    pub fn from_scalar(cmu: bls12_381::Scalar) -> Self {
        Self(cmu)
    }

    /// Parses a tree leaf from the bytes of a Sapling note commitment.
    ///
    /// Returns `None` if the provided bytes represent a non-canonical encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        jubjub::Base::from_repr(bytes).map(Self)
    }

    /// Returns the canonical byte representation of this node.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }

    /// Returns the wrapped value
    #[cfg(feature = "circuit")]
    pub(crate) fn inner(&self) -> &jubjub::Base {
        &self.0
    }

    /// Hashes same-level node pairs together, sharing one inversion across the batch.
    ///
    /// Every pair is evaluated at `level`. As with [`Hashable::combine`], the caller is
    /// responsible for supplying children that belong at that level, and each digest equals
    /// [`Hashable::combine`]'s.
    ///
    /// Returns one digest per input pair, preserving input order.
    pub fn combine_batch<'a>(
        level: Level,
        pairs: impl IntoIterator<Item = (&'a Self, &'a Self)>,
    ) -> Vec<Self> {
        let hashes: Vec<jubjub::ExtendedPoint> = pairs
            .into_iter()
            .map(|(lhs, rhs)| merkle_hash_point(level.into(), &lhs.0.to_bytes(), &rhs.0.to_bytes()))
            .collect();
        let mut affine = vec![jubjub::AffinePoint::identity(); hashes.len()];
        jubjub::ExtendedPoint::batch_normalize(&hashes, &mut affine);
        affine.iter().map(|hash| Node(hash.get_u())).collect()
    }
}

impl Hashable for Node {
    fn empty_leaf() -> Self {
        Node(*UNCOMMITTED_SAPLING)
    }

    fn combine(level: Level, lhs: &Self, rhs: &Self) -> Self {
        let hash = merkle_hash_point(level.into(), &lhs.0.to_bytes(), &rhs.0.to_bytes());
        Node(hash.to_affine().get_u())
    }

    /// - [`Node::combine_batch`] over each task's pairs
    /// - `multicore`: one task per rayon thread, clamped to `MIN..=MAX_PAIRS_PER_TASK` pairs
    fn combine_pairs(level: Level, children: &[Self]) -> Vec<Self> {
        assert!(children.len().is_multiple_of(2), "children pair up");
        let parents = |children: &[Self]| {
            Self::combine_batch(
                level,
                children
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|[lhs, rhs]| (lhs, rhs)),
            )
        };
        #[cfg(feature = "multicore")]
        {
            use rayon::prelude::*;
            let per_task = (children.len() / 2)
                .div_ceil(rayon::current_num_threads())
                .clamp(MIN_PAIRS_PER_TASK, MAX_PAIRS_PER_TASK);
            if children.len() > 2 * per_task {
                return children
                    .par_chunks(2 * per_task)
                    .flat_map_iter(parents)
                    .collect();
            }
        }
        parents(children)
    }

    fn empty_root(level: Level) -> Self {
        EMPTY_ROOTS[<usize>::from(level)]
    }
}

/// Fewest pairs per rayon task (below: pool handoff > the hashing it spreads)
#[cfg(feature = "multicore")]
const MIN_PAIRS_PER_TASK: usize = 32;

/// Most pairs per rayon task (more tasks than threads: balance across P- and E-cores)
#[cfg(feature = "multicore")]
const MAX_PAIRS_PER_TASK: usize = 256;

impl From<Node> for bls12_381::Scalar {
    fn from(node: Node) -> Self {
        node.0
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub(super) mod testing {
    use ff::Field;
    use proptest::prelude::*;
    use rand::{
        distr::{Distribution, StandardUniform},
        Rng,
    };

    use super::Node;
    use crate::note::testing::arb_cmu;

    prop_compose! {
        pub fn arb_node()(cmu in arb_cmu()) -> Node {
            Node::from_cmu(&cmu)
        }
    }

    impl Node {
        /// Return a random fake `MerkleHashOrchard`.
        pub fn random(rng: &mut impl Rng) -> Self {
            StandardUniform.sample(rng)
        }
    }

    impl Distribution<Node> for StandardUniform {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Node {
            Node::from_scalar(bls12_381::Scalar::random(rng))
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use incrementalmerkletree::{Hashable, Level};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use super::{Anchor, Node, NOTE_COMMITMENT_TREE_DEPTH};

    #[test]
    fn combine_batch_matches_combine_at_every_level_and_width() {
        let rng = &mut XorShiftRng::from_seed([5; 16]);
        let pairs: Vec<(Node, Node)> = (0..65)
            .map(|_| (Node::random(rng), Node::random(rng)))
            .collect();

        for level in 0..NOTE_COMMITMENT_TREE_DEPTH {
            let level = Level::from(level);
            for width in [0, 1, 2, 3, 31, 32, 33, 64, 65] {
                let expected: Vec<Node> = pairs[..width]
                    .iter()
                    .map(|(lhs, rhs)| Node::combine(level, lhs, rhs))
                    .collect();
                let actual =
                    Node::combine_batch(level, pairs[..width].iter().map(|(lhs, rhs)| (lhs, rhs)));
                assert_eq!(actual, expected, "level {level:?}, width {width}");
            }
        }
    }

    /// 1000 pairs: several rayon tasks under `multicore` (on any machine with >= 2 threads)
    #[test]
    fn combine_pairs_equals_combine_per_pair_across_task_splits() {
        let rng = &mut XorShiftRng::from_seed([9; 16]);
        let children: Vec<Node> = (0..2 * 1000).map(|_| Node::random(rng)).collect();

        for level in [0, 31].map(Level::from) {
            for pairs in [0, 1, 31, 32, 33, 1000] {
                let children = &children[..2 * pairs];
                let expected: Vec<Node> = children
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|[lhs, rhs]| Node::combine(level, lhs, rhs))
                    .collect();
                assert_eq!(
                    Node::combine_pairs(level, children),
                    expected,
                    "level {level:?}, {pairs} pairs"
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "children pair up")]
    fn combine_pairs_refuses_an_odd_count() {
        Node::combine_pairs(Level::from(0), &[Node::empty_leaf()]);
    }

    /// Published Sapling empty root (zcashd's `3e49b5f9…c2fb`, byte-reversed here)
    #[test]
    fn combine_rebuilds_the_published_empty_root() {
        let root = Anchor::from(Node::empty_root(NOTE_COMMITMENT_TREE_DEPTH.into()));
        assert_eq!(
            hex::encode(root.to_bytes()),
            "fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e"
        );
    }
}
