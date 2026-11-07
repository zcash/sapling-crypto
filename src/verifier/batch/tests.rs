use alloc::vec::Vec;
use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};
use groth16::Proof;
use group::{Group, GroupEncoding};
use rand::{rngs::StdRng, SeedableRng};
use redjubjub::{Binding, SigningKey, SpendAuth};
use zcash_note_encryption::EphemeralKeyBytes;

use super::{BatchValidator, SaplingVerificationContextInner};
use crate::{
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

// Independent streaming reference for check_bundle's preparation and partial queues.
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

fn assert_matches_serial(bundle: Bundle<Authorized, i64>, accepted: bool, signatures_valid: bool) {
    let mut serial = BatchValidator::new();
    assert_eq!(serial_check(&mut serial, &bundle).is_some(), accepted);
    let mut actual = BatchValidator::new();
    assert_eq!(actual.check_bundle(bundle, SIGHASH), accepted);
    assert_eq!(actual.bundles_added, serial.bundles_added);
    // The underlying verifier exposes Debug, but no accessors for queued items.
    assert_eq!(
        format!("{:?}", actual.spend_proofs),
        format!("{:?}", serial.spend_proofs)
    );
    assert_eq!(
        format!("{:?}", actual.output_proofs),
        format!("{:?}", serial.output_proofs)
    );
    assert_eq!(
        serial.signatures.verify(StdRng::seed_from_u64(1)).is_ok(),
        signatures_valid
    );
    assert_eq!(
        actual.signatures.verify(StdRng::seed_from_u64(1)).is_ok(),
        signatures_valid
    );
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

#[test]
fn preparation_matches_serial_at_threshold_boundaries() {
    for (spends, outputs) in [
        (0, 1),
        (1, 0),
        (2, 2),
        (3, 3),
        (4, 0),
        (0, 4),
        (4, 4),
        (5, 5),
    ] {
        assert_matches_serial(bundle(spends, outputs), true, true);
    }
}

#[cfg(feature = "multicore")]
#[test]
fn parallel_threshold_is_per_list() {
    for count in 0..=5 {
        let proofs = (0..count).map(proof_bytes).collect::<Vec<_>>();
        let parsed = super::read_proofs_in_parallel(&proofs, |proof| proof).collect::<Vec<_>>();
        if count < 4 {
            assert!(parsed.is_empty());
        } else {
            let serial = proofs
                .iter()
                .map(|proof| Proof::read(&proof[..]).ok())
                .collect::<Vec<_>>();
            assert_eq!(parsed, serial);
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
fn malformed_proofs_preserve_partial_queues() {
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
        for count in [3, 4, 5] {
            for index in [0, count / 2, count - 1] {
                for output in [false, true] {
                    let bundle = replace_proof(bundle(count, count), output, index, proof);
                    assert_matches_serial(bundle, false, true);
                }
            }
        }
    }
}

#[test]
fn semantic_failures_preserve_partial_queues() {
    for count in [3, 4, 5] {
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
                assert_matches_serial(bundle, false, true);
            }
            let bundle = bundle(count, count);
            let mut spends = bundle.shielded_spends().to_vec();
            let spend = &spends[index];
            spends[index] = SpendDescription::from_parts(
                spend.cv().clone(),
                *spend.anchor(),
                spend.nullifier().clone(),
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
            assert_matches_serial(bundle, false, true);
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
fn signatures_stop_at_the_first_failed_proof() {
    for bad_signature in [0, 2, 4] {
        let bundle = bundle(5, 5).map_authorization(
            0,
            |_, proof| proof,
            |_, proof| proof,
            |index, signature| {
                let replace = *index == bad_signature;
                *index += 1;
                if replace {
                    [0xff; 64].into()
                } else {
                    signature
                }
            },
            |_, auth| auth,
        );
        let bundle = replace_proof(bundle, false, 2, [0; 192]);
        assert_matches_serial(bundle, false, bad_signature >= 2);
    }
    let bundle = bundle(4, 4).map_authorization(
        (),
        |_, proof| proof,
        |_, proof| proof,
        |_, sig| sig,
        |_, _| Authorized {
            binding_sig: [0xff; 64].into(),
        },
    );
    assert_matches_serial(bundle, true, false);
}
