//! Pedersen hashes (without personalisation)
//!
//! A Pedersen commitment to scalar x is
//!     x * g + r * h
//! where g and h are independent base points, and r is random.
//!
//! A Pedersen hash of input m is
//!     m_1 * g_1 + m_2 * g_2 + ... + m_n * g_n
//! where m_1, m_2, ..., m_n are segments of m, and g_1, g_2, ..., g_n are
//! independent base points.
//!
//! For the Merkle tree, the input is two 255-bit field elements of Fr. The
//! JubJub curve has points of order ~252-bit, so we cannot segment simply on
//! field elements.
//!
//! In the circuit, Pedersen hashes are implemented using windowed
//! exponentiation:
//! - Precompute multiples of the bases
//! - Chunk each input segment using a three-bit window
//!   - Two-bit lookup
//!   - Third bit is a sign bit
//!
//! In order to ensure that the possible values for multiples of the base can
//! never collide, we bitshift the generators by 4 bits for each 3-bit window:
//!         0SLL - g
//!     0SLL0000 - g * 2^4
//! 0SLL00000000 - g * 2^8
//!
//! We also want to avoid ever hitting the point at infinity, where addition is
//! undefined. To achieve this, we limit the number of bits for each m_i so that
//! it is at most (s-1)/2, where s is the prime subgroup order of the JubJub
//! curve.
//!
//! The circuit also uses affine Montgomery form, which works fine as long as we
//! don't overflow the scalar. Outside the circuit (here), we just use the
//! twisted Edwards form.

use jubjub::{JubjubParams, PrimeOrder, edwards};
use pairing::{BitIterator, Engine, PrimeField};

fn pedersen_hash<E: Engine, I: Iterator<Item = edwards::Point<E, PrimeOrder>>>(inputs: &[E::Fr], mut bases: I, params: &JubjubParams<E>) -> E::Fr{
    // We want to know ahead of time how many chunks will be used per generator.
    // So pick a generator "space" that is a multiple of our generator bits per
    // chunk, and is comfortably less than the actual generator size.
    // TODO: Check that this value is "comfortably less"
    let generator_space = 248;
    let chunk_size = 3;
    let generator_bits_used_per_chunk = 4;
    let num_chunks = generator_space / generator_bits_used_per_chunk;
    let segment_bits_per_generator = chunk_size * num_chunks;

    // Ensure constants are related by integer multiples
    assert!((E::Fr::NUM_BITS as usize / chunk_size) * chunk_size == E::Fr::NUM_BITS as usize);
    assert!(generator_bits_used_per_chunk * num_chunks == generator_space);

    // Combine inputs into a bitstring
    // TODO: Have BitIterator understand the actual length of x (currently thinks it is 256 bits)
    let bits =
        inputs.iter().flat_map(|x| BitIterator::new(x.into_repr()).skip(1)).collect::<Vec<bool>>();

    let mut res = edwards::Point::zero();
    // Split bitstring into segments
    for segment in bits.chunks(segment_bits_per_generator) {
        // Get the generator for this segment
        // TODO: Handle too few bases
        // TODO: It may be more efficient for bases to return (g, two_g)
        let g = bases.next().unwrap();
        let two_g = g.double(params);

        // Segment is big-endian, so we need to accumulate
        let mut seg_res = edwards::Point::zero();
        for chunk in segment.chunks(chunk_size) {
            // Bit-shift seg_res so individual chunks don't collide
            for _ in 0..generator_bits_used_per_chunk {
                seg_res = seg_res.double(params);
            }

            // Convert each chunk into a multiple of the generator:
            //
            // 000 =       g
            // 001 =      2g
            // 010 = 2g +  g
            // 011 = 2g + 2g
            // 1XX = negate(0XX)
            //
            let mut tmp = g.clone();
            if chunk[2] {
                tmp = tmp.add(&g, params);
            }
            if chunk[1] {
                tmp = tmp.add(&two_g, params);
            }
            if chunk[0] {
                tmp = tmp.negate();
            }

            // Accumulate the chunk
            seg_res = seg_res.add(&tmp, params);
        }

        // Accumulate the segment
        res = res.add(&seg_res, params);
    }

    // Return the x-coordinate of the result, which in a prime-order twisted
    // Edwards subgroup is an injective mapping
    res.into_xy().0
}
