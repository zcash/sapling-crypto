extern crate sapling_crypto;
extern crate bellman;
extern crate rand;
extern crate pairing;

use std::time::{Duration, Instant};
use sapling_crypto::circuit::sprout::*;
use bellman::groth16::*;
use rand::{XorShiftRng, SeedableRng, Rng};
use pairing::bls12_381::Bls12;

use std::fs::File;
use std::io::BufReader;

fn main() {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    // println!("Creating sample parameters...");
    // let groth_params = {
    //     let circuit = JoinSplit {
    //         vpub_old: None,
    //         vpub_new: None,
    //         h_sig: None,
    //         phi: None,
    //         inputs: vec![JSInput {
    //             value: None,
    //             a_sk: None,
    //             rho: None,
    //             r: None,
    //             auth_path: [None; TREE_DEPTH]
    //         }, JSInput {
    //             value: None,
    //             a_sk: None,
    //             rho: None,
    //             r: None,
    //             auth_path: [None; TREE_DEPTH]
    //         }],
    //         outputs: vec![JSOutput {
    //             value: None,
    //             a_pk: None,
    //             r: None
    //         }, JSOutput {
    //             value: None,
    //             a_pk: None,
    //             r: None
    //         }],
    //         rt: None,
    //     };

    //     generate_random_parameters::<Bls12, _, _>(
    //         circuit,
    //         rng
    //     ).unwrap()
    // };
    
    // let mut v: Vec<u8> = vec![];
    // groth_params.write(&mut v).unwrap();
    // println!("{} bytes", v.len());
    // let mut file = File::create("sprout.params").unwrap();
    // file.write_all(&v[..]).unwrap();

    println!("Loading the sample parameters...");

    let reader = File::open("sprout.params").unwrap();
    let reader = BufReader::with_capacity(4096, reader);

    let groth_params = Parameters::<Bls12>::read(reader, false).unwrap();

    println!("Benchmarking...");

    const SAMPLES: u32 = 10;

    let mut total_time = Duration::new(0, 0);
    for _ in 0..SAMPLES {
        let circuit = JoinSplit {
            vpub_old: Some(rng.gen()),
            vpub_new: Some(rng.gen()),
            h_sig: Some(rng.gen()),
            phi: Some(rng.gen()),
            inputs: vec![JSInput {
                value: Some(rng.gen()),
                a_sk: Some(SpendingKey(rng.gen())),
                rho: Some(UniqueRandomness(rng.gen())),
                r: Some(CommitmentRandomness(rng.gen())),
                auth_path: [Some(rng.gen()); TREE_DEPTH]
            }, JSInput {
                value: Some(rng.gen()),
                a_sk: Some(SpendingKey(rng.gen())),
                rho: Some(UniqueRandomness(rng.gen())),
                r: Some(CommitmentRandomness(rng.gen())),
                auth_path: [Some(rng.gen()); TREE_DEPTH]
            }],
            outputs: vec![JSOutput {
                value: Some(rng.gen()),
                a_pk: Some(PayingKey(rng.gen())),
                r: Some(CommitmentRandomness(rng.gen()))
            }, JSOutput {
                value: Some(rng.gen()),
                a_pk: Some(PayingKey(rng.gen())),
                r: Some(CommitmentRandomness(rng.gen()))
            }],
            rt: Some(rng.gen()),
        };

        let start = Instant::now();
        let _ = create_random_proof(circuit, &groth_params, rng).unwrap();
        total_time += start.elapsed();
    }
    let avg = total_time / SAMPLES;
    let avg = avg.subsec_nanos() as f64 / 1_000_000_000f64
              + (avg.as_secs() as f64);

    println!("Average proving time (in seconds): {}", avg);
}
