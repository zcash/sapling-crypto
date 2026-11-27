use alloc::vec::Vec;
use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};
use groth16::Proof;
use group::{Group, GroupEncoding};
use rand::{rngs::StdRng, SeedableRng};
use redjubjub::{Binding, SigningKey, SpendAuth};
use zcash_note_encryption::EphemeralKeyBytes;

use super::{
    read_proofs, BatchValidator, SaplingVerificationContextInner, PARALLEL_PARSE_THRESHOLD,
};
use crate::{
    builder::testing::proven_two_spend_bundle,
    bundle::{Authorized, Bundle, GrothProofBytes, OutputDescription, SpendDescription},
    note::ExtractedNoteCommitment,
    note_encryption::ENC_CIPHERTEXT_SIZE,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Nullifier,
};

const SIGHASH: [u8; 32] = [42; 32];

// Construct distinct, correctly encoded curve points. These are parser fixtures, not
// Sapling circuit proofs; comparing the queued proofs and inputs also checks attribution.
fn proof_bytes(index: u64) -> GrothProofBytes {
    let proof = Proof::<Bls12> {
        a: (G1Affine::generator() * Scalar::from(index + 1)).into(),
        b: G2Affine::generator(),
        c: (G1Affine::generator() * Scalar::from(index + 2)).into(),
    };
    let mut bytes = [0; 192];
    proof.write(&mut bytes[..]).unwrap();
    bytes
}

fn bundle(spends: usize, outputs: usize) -> Bundle<Authorized, i64> {
    let mut rng = StdRng::seed_from_u64(0);
    let sk = SigningKey::<SpendAuth>::new(&mut rng);
    let cv = || {
        ValueCommitment::derive(
            NoteValue::ZERO,
            ValueCommitTrapdoor::from_bytes(jubjub::Scalar::one().to_bytes()).unwrap(),
        )
    };
    let bsk = SigningKey::<Binding>::from_bytes(
        &(jubjub::Scalar::from(u64::try_from(spends).unwrap())
            - jubjub::Scalar::from(u64::try_from(outputs).unwrap()))
        .to_bytes(),
    )
    .unwrap();
    Bundle::from_parts(
        (0..spends)
            .map(|i| {
                let index = u64::try_from(i).unwrap();
                SpendDescription::from_parts(
                    cv(),
                    Scalar::from(index),
                    Nullifier(Scalar::from(index + 1).to_bytes()),
                    (&sk).into(),
                    proof_bytes(index),
                    sk.sign(&mut rng, &SIGHASH),
                )
            })
            .collect(),
        (0..outputs)
            .map(|i| {
                let index = u64::try_from(i).unwrap() + 16;
                OutputDescription::from_parts(
                    cv(),
                    ExtractedNoteCommitment::from_bytes(&Scalar::from(index).to_bytes()).unwrap(),
                    EphemeralKeyBytes(jubjub::ExtendedPoint::generator().to_bytes()),
                    [0; ENC_CIPHERTEXT_SIZE],
                    [0; 80],
                    proof_bytes(index),
                )
            })
            .collect(),
        0,
        Authorized {
            binding_sig: bsk.sign(&mut rng, &SIGHASH),
        },
    )
    .unwrap()
}

// Independent streaming reference for check_bundle's decision and queued items.
fn serial_check(validator: &mut BatchValidator, bundle: &Bundle<Authorized, i64>) -> Option<()> {
    validator.bundles_added = true;
    let mut ctx = SaplingVerificationContextInner::new();
    for spend in bundle.shielded_spends() {
        let proof = Proof::read(&spend.zkproof()[..]).ok()?;
        if !ctx.check_spend(
            spend.cv(),
            *spend.anchor(),
            &spend.nullifier().0,
            spend.rk(),
            proof,
            validator,
            |validator, rk| {
                validator
                    .signatures
                    .queue(((*rk).into(), *spend.spend_auth_sig(), &SIGHASH));
                true
            },
            |validator, proof, inputs| {
                validator.spend_proofs.queue((proof, inputs.to_vec()));
                true
            },
        ) {
            return None;
        }
    }
    for output in bundle.shielded_outputs() {
        let epk = Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(
            &output.ephemeral_key().0,
        ))?;
        let proof = Proof::read(&output.zkproof()[..]).ok()?;
        if !ctx.check_output(output.cv(), *output.cmu(), epk, proof, |proof, inputs| {
            validator.output_proofs.queue((proof, inputs.to_vec()));
            true
        }) {
            return None;
        }
    }
    ctx.final_check(*bundle.value_balance(), |bvk| {
        validator
            .signatures
            .queue((bvk.into(), bundle.authorization().binding_sig, &SIGHASH));
        true
    })
    .then_some(())
}

/// Asserts that both `check_bundle` and the serial reference accept `bundle`, and that
/// they queue the same proofs in the same order. Returns whether the signatures queued
/// by `check_bundle` verify, after asserting that the reference's signatures agree.
fn assert_accepted_like_serial(bundle: Bundle<Authorized, i64>) -> bool {
    let mut serial = BatchValidator::new();
    assert!(serial_check(&mut serial, &bundle).is_some());
    let mut actual = BatchValidator::new();
    assert!(actual.check_bundle(bundle, SIGHASH));
    // The underlying verifier exposes Debug, but no accessors for queued items.
    assert_eq!(
        format!("{:?}", actual.spend_proofs),
        format!("{:?}", serial.spend_proofs)
    );
    assert_eq!(
        format!("{:?}", actual.output_proofs),
        format!("{:?}", serial.output_proofs)
    );
    let signatures_valid = actual.signatures.verify(StdRng::seed_from_u64(1)).is_ok();
    assert_eq!(
        serial.signatures.verify(StdRng::seed_from_u64(1)).is_ok(),
        signatures_valid
    );
    signatures_valid
}

/// Asserts that both `check_bundle` and the serial reference reject `bundle`.
fn assert_rejected_like_serial(bundle: Bundle<Authorized, i64>) {
    assert!(serial_check(&mut BatchValidator::new(), &bundle).is_none());
    assert!(!BatchValidator::new().check_bundle(bundle, SIGHASH));
}

fn replace_proof(
    bundle: Bundle<Authorized, i64>,
    output: bool,
    index: usize,
    replacement: GrothProofBytes,
) -> Bundle<Authorized, i64> {
    bundle.map_authorization(
        (0, 0),
        |indices, proof| {
            let replace = !output && indices.0 == index;
            indices.0 += 1;
            if replace {
                replacement
            } else {
                proof
            }
        },
        |indices, proof| {
            let replace = output && indices.1 == index;
            indices.1 += 1;
            if replace {
                replacement
            } else {
                proof
            }
        },
        |_, sig| sig,
        |_, auth| auth,
    )
}

/// Returns the list lengths just below, at, and just above the parallel parsing threshold.
fn counts_around_threshold() -> [usize; 3] {
    [
        PARALLEL_PARSE_THRESHOLD - 1,
        PARALLEL_PARSE_THRESHOLD,
        PARALLEL_PARSE_THRESHOLD + 1,
    ]
}

#[test]
fn preparation_matches_serial_at_threshold_boundaries() {
    let threshold = PARALLEL_PARSE_THRESHOLD;
    for (spends, outputs) in [
        (0, 1),
        (1, 0),
        (threshold - 2, threshold - 2),
        (threshold - 1, threshold - 1),
        (threshold, 0),
        (0, threshold),
        (threshold, threshold),
        (threshold + 1, threshold + 1),
    ] {
        assert!(assert_accepted_like_serial(bundle(spends, outputs)));
    }
}

#[test]
fn read_proofs_preserves_order_and_rejects_any_malformed_proof() {
    for count in 0..=PARALLEL_PARSE_THRESHOLD + 1 {
        let proofs = (0..count)
            .map(|index| proof_bytes(u64::try_from(index).unwrap()))
            .collect::<Vec<_>>();
        let serial = proofs
            .iter()
            .map(|proof| Proof::read(&proof[..]).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(read_proofs(&proofs, |proof| proof), Some(serial));
        for index in 0..proofs.len() {
            let mut proofs = proofs.clone();
            proofs[index] = [0; 192];
            assert_eq!(read_proofs(&proofs, |proof| proof), None);
        }
    }
}

#[cfg(feature = "multicore")]
#[test]
fn preparation_matches_serial_with_one_worker() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(preparation_matches_serial_at_threshold_boundaries);
}

#[test]
fn malformed_proofs_reject_like_serial() {
    let valid = proof_bytes(0);
    let mut malformed = Vec::new();
    for (start, end) in [(0, 48), (48, 144), (144, 192)] {
        let mut noncanonical = valid;
        noncanonical[start..end].fill(0xff);
        malformed.push(noncanonical);
        let mut infinity = valid;
        infinity[start..end].fill(0);
        infinity[start] = 0xc0;
        malformed.push(infinity);
    }
    // (0, 2) is on G1 but has order three, not the prime subgroup order.
    let mut torsion = valid;
    torsion[..48].fill(0);
    torsion[0] = 0x80;
    let point = G1Affine::from_compressed_unchecked(torsion[..48].try_into().unwrap()).unwrap();
    assert!(!bool::from(point.is_torsion_free()));
    malformed.push(torsion);
    let mut torsion_c = valid;
    torsion_c[144..].copy_from_slice(&torsion[..48]);
    malformed.push(torsion_c);
    // Find an on-curve G2 encoding outside its prime-order subgroup.
    let torsion_g2 = (0..=255u8)
        .find_map(|x| {
            let mut bytes = [0; 96];
            bytes[0] = 0x80;
            bytes[95] = x;
            Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&bytes))
                .filter(|point| !bool::from(point.is_torsion_free()))
                .map(|_| bytes)
        })
        .expect("small G2 x coordinates include points outside the prime-order subgroup");
    let mut torsion = valid;
    torsion[48..144].copy_from_slice(&torsion_g2);
    malformed.push(torsion);
    for proof in malformed {
        assert!(Proof::<Bls12>::read(&proof[..]).is_err());
        for count in counts_around_threshold() {
            for index in [0, count / 2, count - 1] {
                for output in [false, true] {
                    let bundle = replace_proof(bundle(count, count), output, index, proof);
                    assert_rejected_like_serial(bundle);
                }
            }
        }
    }
}

#[test]
fn semantic_failures_reject_like_serial() {
    for count in counts_around_threshold() {
        for index in [0, count / 2, count - 1] {
            for epk in [[0xff; 32], jubjub::ExtendedPoint::identity().to_bytes()] {
                let bundle = bundle(count, count);
                let mut outputs = bundle.shielded_outputs().to_vec();
                *outputs[index].ephemeral_key_mut() = EphemeralKeyBytes(epk);
                let bundle = Bundle::from_parts(
                    bundle.shielded_spends().to_vec(),
                    outputs,
                    0,
                    *bundle.authorization(),
                )
                .unwrap();
                assert_rejected_like_serial(bundle);
            }
            let bundle = bundle(count, count);
            let mut spends = bundle.shielded_spends().to_vec();
            let spend = &spends[index];
            spends[index] = SpendDescription::from_parts(
                spend.cv().clone(),
                *spend.anchor(),
                *spend.nullifier(),
                jubjub::ExtendedPoint::identity()
                    .to_bytes()
                    .try_into()
                    .unwrap(),
                *spend.zkproof(),
                *spend.spend_auth_sig(),
            );
            let bundle = Bundle::from_parts(
                spends,
                bundle.shielded_outputs().to_vec(),
                0,
                *bundle.authorization(),
            )
            .unwrap();
            assert_rejected_like_serial(bundle);
        }
    }
    // Invalid commitments cannot enter a decoded bundle through the network constructors.
    assert!(bool::from(
        ValueCommitment::from_bytes_not_small_order(&jubjub::ExtendedPoint::identity().to_bytes(),)
            .is_none()
    ));
    assert!(bool::from(
        ValueCommitment::from_bytes_not_small_order(&[0xff; 32]).is_none()
    ));
    assert!(bool::from(
        ExtractedNoteCommitment::from_bytes(&[0xff; 32]).is_none()
    ));
}

#[test]
fn accepted_bundle_queues_its_binding_signature() {
    let bundle = bundle(PARALLEL_PARSE_THRESHOLD, PARALLEL_PARSE_THRESHOLD).map_authorization(
        (),
        |_, proof| proof,
        |_, proof| proof,
        |_, sig| sig,
        |_, _| Authorized {
            binding_sig: [0xff; 64].into(),
        },
    );
    assert!(!assert_accepted_like_serial(bundle));
}

fn decodable_proof() -> GrothProofBytes {
    let proof = groth16::Proof::<bls12_381::Bls12> {
        a: bls12_381::G1Affine::generator(),
        b: bls12_381::G2Affine::generator(),
        c: bls12_381::G1Affine::generator(),
    };
    let mut bytes = Vec::new();
    proof.write(&mut bytes).unwrap();
    bytes.try_into().unwrap()
}

/// Replaces the mock proofs, which are all zeroes and thus do not decode, with
/// encodable proofs. Signature batch validation does not use the proofs.
fn with_decodable_proofs(bundle: Bundle<Authorized, i64>) -> Bundle<Authorized, i64> {
    let proof = decodable_proof();
    let spends = bundle
        .shielded_spends()
        .iter()
        .map(|spend| {
            SpendDescription::from_parts(
                spend.cv().clone(),
                *spend.anchor(),
                *spend.nullifier(),
                *spend.rk(),
                proof,
                *spend.spend_auth_sig(),
            )
        })
        .collect();
    let outputs = bundle
        .shielded_outputs()
        .iter()
        .map(|output| {
            OutputDescription::from_parts(
                output.cv().clone(),
                *output.cmu(),
                output.ephemeral_key().clone(),
                *output.enc_ciphertext(),
                *output.out_ciphertext(),
                proof,
            )
        })
        .collect();
    Bundle::from_parts(
        spends,
        outputs,
        *bundle.value_balance(),
        Authorized {
            binding_sig: bundle.authorization().binding_sig,
        },
    )
    .unwrap()
}

#[test]
fn queues_each_spend_and_binding_under_their_own_sighash() {
    let mut rng = StdRng::seed_from_u64(1);
    let (bundle, ask) = proven_two_spend_bundle();
    let spend_sighashes = [[1; 32], [2; 32]];
    let binding_sighash = [3; 32];
    let bundle = with_decodable_proofs(
        bundle
            .apply_signatures_with_sighashes(
                &mut rng,
                &spend_sighashes,
                binding_sighash,
                core::slice::from_ref(&ask),
            )
            .unwrap(),
    );

    let mut validator = BatchValidator::new();
    assert!(validator.check_bundle_with_sighashes(
        bundle.clone(),
        &spend_sighashes,
        binding_sighash,
    ));
    assert!(validator.signatures.verify(&mut rng).is_ok());

    // The same signatures do not verify when the per-spend digests are not matched
    // to their spends.
    let mut validator = BatchValidator::new();
    assert!(validator.check_bundle_with_sighashes(
        bundle,
        &[spend_sighashes[1], spend_sighashes[0]],
        binding_sighash,
    ));
    assert!(validator.signatures.verify(&mut rng).is_err());
}

#[test]
fn rejects_mismatched_sighash_count() {
    let mut rng = StdRng::seed_from_u64(2);
    let (bundle, ask) = proven_two_spend_bundle();
    let spend_sighashes = [[1; 32], [2; 32]];
    let binding_sighash = [3; 32];
    let authorized = with_decodable_proofs(
        bundle
            .apply_signatures_with_sighashes(
                &mut rng,
                &spend_sighashes,
                binding_sighash,
                core::slice::from_ref(&ask),
            )
            .unwrap(),
    );

    let mut validator = BatchValidator::new();
    assert!(!validator.check_bundle_with_sighashes(
        authorized.clone(),
        &spend_sighashes[..1],
        binding_sighash,
    ));

    let mut validator = BatchValidator::new();
    assert!(!validator.check_bundle_with_sighashes(
        authorized.clone(),
        &[spend_sighashes[0], spend_sighashes[1], [4; 32]],
        binding_sighash,
    ));

    let mut validator = BatchValidator::new();
    assert!(validator.check_bundle_with_sighashes(authorized, &spend_sighashes, binding_sighash));
    assert!(validator.signatures.verify(&mut rng).is_ok());
}

#[test]
fn shared_sighash_wrapper_queues_the_shared_digest() {
    let mut rng = StdRng::seed_from_u64(3);
    let (bundle, ask) = proven_two_spend_bundle();
    let sighash = [4; 32];
    let bundle = with_decodable_proofs(
        bundle
            .apply_signatures(&mut rng, sighash, core::slice::from_ref(&ask))
            .unwrap(),
    );

    let mut validator = BatchValidator::new();
    assert!(validator.check_bundle(bundle, sighash));
    assert!(validator.signatures.verify(&mut rng).is_ok());
}
