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
    /// Consumes the input iterator once and returns one digest per pair, preserving order.
    /// An empty iterator returns an empty vector.
    pub fn combine_batch<'a>(
        level: Level,
        pairs: impl IntoIterator<Item = (&'a Self, &'a Self)>,
    ) -> Vec<Self> {
        let mut pairs = pairs.into_iter().peekable();
        let Some((lhs, rhs)) = pairs.next() else {
            return Vec::new();
        };
        if pairs.peek().is_none() {
            return vec![Self::combine(level, lhs, rhs)];
        }

        let mut hashes: Vec<jubjub::ExtendedPoint> = core::iter::once((lhs, rhs))
            .chain(pairs)
            .map(|(lhs, rhs)| merkle_hash_point(level.into(), &lhs.0.to_bytes(), &rhs.0.to_bytes()))
            .collect();
        jubjub::batch_normalize(&mut hashes)
            .map(|hash| Node(hash.get_u()))
            .collect()
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

    /// Hashes pairs with [`Node::combine_batch`], splitting wide batches under `multicore`.
    ///
    /// Wide batches use the current rayon pool, initializing the global pool if called
    /// outside a rayon worker. Batches with fewer than 64 pairs do not access rayon.
    fn combine_pairs<'a, I>(level: Level, pairs: I) -> Vec<Self>
    where
        Self: 'a,
        I: IntoIterator<Item = (&'a Self, &'a Self)>,
    {
        #[cfg(feature = "multicore")]
        {
            use rayon::prelude::*;
            let pairs = pairs.into_iter();
            if pairs
                .size_hint()
                .1
                .is_some_and(|len| len < 2 * MIN_PAIRS_PER_TASK)
            {
                return Self::combine_batch(level, pairs);
            }
            let pairs: Vec<_> = pairs.collect();
            if pairs.len() < 2 * MIN_PAIRS_PER_TASK {
                return Self::combine_batch(level, pairs);
            }
            let threads = rayon::current_num_threads();
            if threads == 1 {
                return Self::combine_batch(level, pairs);
            }
            let per_task = pairs
                .len()
                .div_ceil(threads)
                .clamp(MIN_PAIRS_PER_TASK, MAX_PAIRS_PER_TASK);
            if pairs.len() > per_task {
                return pairs
                    .par_chunks(per_task)
                    .flat_map_iter(|pairs| Self::combine_batch(level, pairs.iter().copied()))
                    .collect();
            }
            Self::combine_batch(level, pairs)
        }
        #[cfg(not(feature = "multicore"))]
        {
            Self::combine_batch(level, pairs)
        }
    }

    fn empty_root(level: Level) -> Self {
        EMPTY_ROOTS[<usize>::from(level)]
    }
}

/// Minimum target chunk size; the final chunk can contain fewer pairs.
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
    use incrementalmerkletree::{
        frontier::Frontier, testing::check_combine_pairs, Hashable, Level,
    };
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use super::{merkle_hash, Anchor, Node, NOTE_COMMITMENT_TREE_DEPTH};

    #[test]
    fn public_merkle_hash_matches_reference_for_arbitrary_child_bytes() {
        use crate::pedersen_hash::{pedersen_hash, Personalization};
        use group::Curve;

        let mut high_bit = [0; 32];
        high_bit[31] = 0x80;
        for depth in [0, 31, 62] {
            for (mut lhs, mut rhs) in [
                ([0; 32], [0; 32]),
                ([0xff; 32], [0xff; 32]),
                (high_bit, [0; 32]),
                ([0; 32], high_bit),
                ([0x55; 32], [0xaa; 32]),
            ] {
                let bits = |child: [u8; 32]| {
                    (0..255).map(move |bit| (child[bit / 8] >> (bit % 8)) & 1 != 0)
                };
                let expected = jubjub::ExtendedPoint::from(pedersen_hash(
                    Personalization::MerkleTree(depth),
                    bits(lhs).chain(bits(rhs)),
                ))
                .to_affine()
                .get_u()
                .to_bytes();
                assert_eq!(merkle_hash(depth, &lhs, &rhs), expected);
                lhs[31] ^= 0x80;
                assert_eq!(merkle_hash(depth, &lhs, &rhs), expected);
                rhs[31] ^= 0x80;
                assert_eq!(merkle_hash(depth, &lhs, &rhs), expected);
            }
        }
    }

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

    #[test]
    fn combine_pairs_equals_combine_per_pair_across_task_splits() {
        check_pair_batches();
    }

    fn check_pair_batches() {
        let rng = &mut XorShiftRng::from_seed([9; 16]);
        let pairs: Vec<_> = (0..1000)
            .map(|_| (Node::random(rng), Node::random(rng)))
            .collect();

        for level in [0, 31, 62].map(Level::from) {
            for width in [
                0, 1, 2, 3, 31, 32, 33, 63, 64, 65, 255, 256, 257, 511, 512, 513, 1000,
            ] {
                check_combine_pairs(level, &pairs[..width]);
            }
        }
    }

    #[cfg(feature = "multicore")]
    #[test]
    fn combine_pairs_preserves_order_in_explicit_thread_pools() {
        for threads in [1, 2, 4] {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    check_pair_batches();
                    check_non_send_iterators();
                });
        }
    }

    #[test]
    fn combine_pairs_consumes_non_send_iterators_once() {
        check_non_send_iterators();
    }

    fn check_non_send_iterators() {
        use alloc::rc::Rc;
        use core::cell::Cell;

        let rng = &mut XorShiftRng::from_seed([11; 16]);
        let pairs: Vec<_> = (0..1000)
            .map(|_| (Node::random(rng), Node::random(rng)))
            .collect();
        let level = Level::from(15);
        for width in [0, 1, 33, 63, 1000] {
            let expected: Vec<_> = pairs[..width]
                .iter()
                .map(|(lhs, rhs)| Node::combine(level, lhs, rhs))
                .collect();
            for source in [&pairs[..width], &pairs[..]] {
                let reads = Rc::new(Cell::new(0));
                let input = source
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| {
                        reads.set(reads.get() + 1);
                        *i < width
                    })
                    .map(|(_, (lhs, rhs))| (lhs, rhs));
                assert_eq!(Node::combine_pairs(level, input), expected);
                assert_eq!(reads.get(), source.len());
            }

            let reads = Rc::new(Cell::new(0));
            let mut source = pairs[..width].iter();
            let input = core::iter::from_fn(|| source.next()).map(|(lhs, rhs)| {
                reads.set(reads.get() + 1);
                (lhs, rhs)
            });
            assert_eq!(input.size_hint(), (0, None));
            assert_eq!(Node::combine_pairs(level, input), expected);
            assert_eq!(reads.get(), width);
        }
    }

    #[test]
    fn frontier_batch_appends_match_per_leaf_appends() {
        use core::convert::Infallible;

        let rng = &mut XorShiftRng::from_seed([13; 16]);
        let leaves: Vec<_> = (0..1024).map(|_| Node::random(rng)).collect();
        for start in [0, 1, 2, 3, 31, 32, 33, 255, 256, 257] {
            let mut expected = Frontier::<Node, NOTE_COMMITMENT_TREE_DEPTH>::empty();
            for leaf in &leaves[..start] {
                assert!(expected.append(*leaf));
            }
            let mut batched = expected.clone();
            let mut visiting = expected.clone();
            let mut offset = start;
            for width in [0, 1, 2, 31, 32, 33, 64, 65, 257] {
                let batch = &leaves[offset..offset + width];
                for leaf in batch {
                    assert!(expected.append(*leaf));
                }
                assert!(batched.append_batch(batch));
                assert_eq!(
                    visiting.append_batch_visiting(batch, |_, _| Ok::<(), Infallible>(())),
                    Ok(true)
                );
                assert_eq!(
                    batched, expected,
                    "start {start}, offset {offset}, width {width}"
                );
                assert_eq!(
                    visiting, expected,
                    "start {start}, offset {offset}, width {width}"
                );
                assert_eq!(batched.root(), expected.root());
                assert_eq!(visiting.root(), expected.root());
                offset += width;
            }
        }
    }

    #[test]
    fn frontier_rejects_oversized_batches_without_changing_the_root() {
        let mut frontier = Frontier::<Node, 4>::empty();
        assert!(frontier.append_batch(&[Node::empty_leaf(); 15]));
        let before = frontier.clone();
        let root = frontier.root();
        assert!(!frontier.append_batch(&[Node::empty_leaf(); 2]));
        assert_eq!(frontier, before);
        assert_eq!(frontier.root(), root);
        assert!(frontier.append_batch(&[Node::empty_leaf()]));
        assert_eq!(frontier.root(), Node::empty_root(Level::from(4)));
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
