use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use group::{Group, GroupEncoding};
use rand::{rngs::StdRng, SeedableRng};
use redjubjub::{SigningKey, SpendAuth};
use sapling_crypto::{
    bundle::{Authorized, Bundle, OutputDescription, SpendDescription},
    note::ExtractedNoteCommitment,
    note_encryption::ENC_CIPHERTEXT_SIZE,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    BatchValidator, Nullifier,
};
use zcash_note_encryption::EphemeralKeyBytes;

// These proofs contain correctly encoded subgroup points, not valid circuit proofs.
// check_bundle parses and queues them; this benchmark does not call validate.
fn bundle(spends: usize, outputs: usize) -> Bundle<Authorized, i64> {
    let mut rng = StdRng::seed_from_u64(0);
    let sk = SigningKey::<SpendAuth>::new(&mut rng);
    let cv = ValueCommitment::derive(
        NoteValue::ZERO,
        ValueCommitTrapdoor::from_bytes(jubjub::Scalar::one().to_bytes()).unwrap(),
    );
    let proof_bytes = |index: usize| {
        let index = u64::try_from(index).unwrap();
        let proof = groth16::Proof::<Bls12> {
            a: (G1Affine::generator() * Scalar::from(index + 1)).into(),
            b: G2Affine::generator(),
            c: (G1Affine::generator() * Scalar::from(index + 2)).into(),
        };
        let mut bytes = [0; 192];
        proof.write(&mut bytes[..]).unwrap();
        bytes
    };
    Bundle::from_parts(
        (0..spends)
            .map(|i| {
                SpendDescription::from_parts(
                    cv.clone(),
                    Scalar::from(u64::try_from(i).unwrap()),
                    Nullifier([0; 32]),
                    (&sk).into(),
                    proof_bytes(i),
                    [0; 64].into(),
                )
            })
            .collect(),
        (0..outputs)
            .map(|i| {
                OutputDescription::from_parts(
                    cv.clone(),
                    ExtractedNoteCommitment::from_bytes(&Scalar::from(1).to_bytes()).unwrap(),
                    EphemeralKeyBytes(jubjub::ExtendedPoint::generator().to_bytes()),
                    [0; ENC_CIPHERTEXT_SIZE],
                    [0; 80],
                    proof_bytes(spends + i),
                )
            })
            .collect(),
        0,
        Authorized {
            binding_sig: [0; 64].into(),
        },
    )
    .unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sapling-check-bundle");
    for (spends, outputs) in [(1, 2), (3, 3), (4, 4), (16, 16), (128, 128), (0, 1000)] {
        let bundle = bundle(spends, outputs);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{spends}-spends-{outputs}-outputs")),
            &bundle,
            |b, bundle| {
                b.iter_batched(
                    || (BatchValidator::new(), bundle.clone()),
                    |(mut validator, bundle)| {
                        assert!(validator.check_bundle(black_box(bundle), [42; 32]));
                        black_box(validator)
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
