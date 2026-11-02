use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use ff::Field;
use incrementalmerkletree::{Hashable, Level};
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

#[cfg(unix)]
criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_pedersen_hash, bench_merkle
}
#[cfg(not(unix))]
criterion_group!(benches, bench_pedersen_hash, bench_merkle);
criterion_main!(benches);
