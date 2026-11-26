//! Measure first-call latency, including lazy initialization, separately from warm hashing.
//!
//! Run each configuration in a fresh process:
//!
//! ```sh
//! cargo run --locked --release --example merkle_hash_timing
//! cargo run --locked --release --example merkle_hash_timing --features runtime-precomputation
//! ```
//!
//! Record the CPU and Rust version alongside results. Compare several fresh runs;
//! these one-shot timings are sensitive to system load. When precomputation saves
//! time per warm hash, a rough break-even count is one plus the added first-call
//! latency divided by that per-hash saving. Use Criterion for steady-state comparisons.

use std::{hint::black_box, time::Instant};

use sapling_crypto::merkle_hash;

fn main() {
    let (lhs, rhs) = ([0x55; 32], [0xaa; 32]);
    let start = Instant::now();
    black_box(merkle_hash(15, black_box(&lhs), black_box(&rhs)));
    let first = start.elapsed();

    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(merkle_hash(15, black_box(&lhs), black_box(&rhs)));
    }
    let warm = start.elapsed() / iterations;

    println!(
        "runtime-precomputation: {}",
        cfg!(feature = "runtime-precomputation")
    );
    println!("first hash, including initialization: {first:?}");
    println!("warm hash, mean of {iterations}: {warm:?}");
}
