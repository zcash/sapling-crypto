//! Compare precomputation off/on at the same commit, with the same thread count:
//!
//! ```sh
//! RAYON_NUM_THREADS=1 cargo bench --locked --bench pedersen_hash -- --save-baseline off
//! RAYON_NUM_THREADS=1 cargo bench --locked --bench pedersen_hash --features runtime-precomputation -- --baseline off
//! ```
//!
//! Record the CPU, Rust version, features and thread count with results. Parallel
//! benchmark IDs include the current pool size; scalar and serial-batch IDs are stable.
//! Criterion measures steady-state hashing after initialization. For first-call cost,
//! run the `merkle_hash_timing` example in a fresh process with each feature configuration.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use ff::Field;
use incrementalmerkletree::{frontier::Frontier, Hashable, Level};
use rand_core::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use sapling_crypto::{
    pedersen_hash::{pedersen_hash, Personalization},
    Node,
};

#[cfg(unix)]
use pprof::criterion::{Output, PProfProfiler};

/// Same inputs every run (A/B runs compare identical work)
fn rng() -> XorShiftRng {
    XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ])
}

fn bits(rng: &mut XorShiftRng, n: usize) -> Vec<bool> {
    (0..n).map(|_| !rng.next_u32().is_multiple_of(2)).collect()
}

fn nodes(rng: &mut XorShiftRng, n: usize) -> Vec<Node> {
    (0..n)
        .map(|_| Node::from_scalar(bls12_381::Scalar::random(&mut *rng)))
        .collect()
}

fn pool_threads() -> usize {
    #[cfg(feature = "multicore")]
    {
        rayon::current_num_threads()
    }
    #[cfg(not(feature = "multicore"))]
    {
        1
    }
}

fn bench_pedersen_hash(c: &mut Criterion) {
    let rng = &mut rng();
    let merkle = bits(rng, 510);
    let note = bits(rng, 576);

    let mut group = c.benchmark_group("pedersen_hash");
    group.bench_function("merkle_516", |b| {
        b.iter(|| {
            pedersen_hash(
                Personalization::MerkleTree(31),
                black_box(&merkle).iter().copied(),
            )
        })
    });
    group.bench_function("note_commitment_582", |b| {
        b.iter(|| {
            pedersen_hash(
                Personalization::NoteCommitment,
                black_box(&note).iter().copied(),
            )
        })
    });
    group.finish();
}

fn bench_merkle(c: &mut Criterion) {
    let rng = &mut rng();
    let children = nodes(rng, 128);
    let level = Level::from(15);

    let mut group = c.benchmark_group("merkle");
    group.bench_function("combine", |b| {
        b.iter(|| Node::combine(level, black_box(&children[0]), black_box(&children[1])))
    });
    group.throughput(Throughput::Elements(64));
    group.bench_function("level_64", |b| {
        b.iter(|| {
            black_box(&children)
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[lhs, rhs]| Node::combine(level, lhs, rhs))
                .collect::<Vec<_>>()
        })
    });
    group.bench_function("combine_batch_64", |b| {
        b.iter(|| {
            let pairs = black_box(&children)
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[lhs, rhs]| (lhs, rhs));
            Node::combine_batch(level, pairs)
        })
    });
    group.finish();
}

fn bench_pair_batches(c: &mut Criterion) {
    let children = nodes(&mut rng(), 2000);
    let level = Level::from(15);
    let hook_name = format!("hook_{}_threads", pool_threads());
    let mut group = c.benchmark_group("merkle_pairs");
    for width in [1, 31, 32, 33, 64, 255, 256, 257, 1000] {
        let pairs = children[..2 * width].as_chunks::<2>().0;
        group.throughput(Throughput::Elements(width as u64));
        group.bench_with_input(BenchmarkId::new("scalar", width), pairs, |b, pairs| {
            b.iter(|| {
                black_box(pairs)
                    .iter()
                    .map(|[lhs, rhs]| Node::combine(level, lhs, rhs))
                    .collect::<Vec<_>>()
            })
        });
        group.bench_with_input(BenchmarkId::new("batch", width), pairs, |b, pairs| {
            b.iter(|| {
                Node::combine_batch(level, black_box(pairs).iter().map(|[lhs, rhs]| (lhs, rhs)))
            })
        });
        group.bench_with_input(BenchmarkId::new(&hook_name, width), pairs, |b, pairs| {
            b.iter(|| {
                Node::combine_pairs(level, black_box(pairs).iter().map(|[lhs, rhs]| (lhs, rhs)))
            })
        });
    }
    group.finish();
}

fn bench_frontier(c: &mut Criterion) {
    let children = nodes(&mut rng(), 2257);
    let mut prior = Frontier::<Node, 32>::empty();
    for leaf in &children[..257] {
        assert!(prior.append(*leaf));
    }

    let batch_name = format!("batch_{}_threads", pool_threads());
    let mut group = c.benchmark_group("frontier");
    for width in [1, 32, 100, 2000] {
        let leaves = &children[257..257 + width];
        group.throughput(Throughput::Elements(width as u64));
        group.bench_with_input(BenchmarkId::new("scalar", width), leaves, |b, leaves| {
            b.iter_batched(
                || prior.clone(),
                |mut frontier| {
                    for leaf in black_box(leaves) {
                        assert!(frontier.append(*leaf));
                    }
                    black_box(frontier.root())
                },
                BatchSize::SmallInput,
            )
        });
        group.bench_with_input(BenchmarkId::new(&batch_name, width), leaves, |b, leaves| {
            b.iter_batched(
                || prior.clone(),
                |mut frontier| {
                    assert!(frontier.append_batch(black_box(leaves).iter().copied()));
                    black_box(frontier.root())
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

#[cfg(unix)]
criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_pedersen_hash, bench_merkle, bench_pair_batches, bench_frontier
}
#[cfg(not(unix))]
criterion_group!(
    benches,
    bench_pedersen_hash,
    bench_merkle,
    bench_pair_batches,
    bench_frontier
);
criterion_main!(benches);
