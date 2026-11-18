//! Opt-in deferral of value commitment decompression for encodings the caller already validated.

/// Runs `f` with decompression of value commitments parsed on this thread deferred to first use.
///
/// Inside the scope, [`ValueCommitment::from_bytes_not_small_order`] accepts any 32 bytes, and
/// [`ValueCommitment::to_bytes`] returns them unchanged. The canonical-encoding and small-order
/// checks run when the commitment is first used, and the decoded point is kept. If the checks
/// fail, the Sapling verifiers reject the spend or output, and other uses (such as
/// [`ValueCommitment::as_inner`] or summing commitments) panic.
///
/// Only use it for encodings this library accepted before, such as transactions a node reads
/// back from its own verified state. Never parse network input inside it.
///
/// The flag is per thread, so `f` must not block on rayon (`join`, `scope`, `par_iter`) or drive
/// an executor, or other jobs run on this thread meanwhile would parse with trust on.
///
/// Without the `std` feature this is a no-op: `f` runs and commitments are decoded eagerly.
///
/// [`ValueCommitment::from_bytes_not_small_order`]: crate::value::ValueCommitment::from_bytes_not_small_order
/// [`ValueCommitment::to_bytes`]: crate::value::ValueCommitment::to_bytes
/// [`ValueCommitment::as_inner`]: crate::value::ValueCommitment::as_inner
pub fn with_trusted_encodings<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(feature = "std")]
    {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                TRUSTED.with(|trusted| trusted.set(self.0));
            }
        }
        let _restore = Restore(TRUSTED.with(|trusted| trusted.replace(true)));
        f()
    }
    #[cfg(not(feature = "std"))]
    f()
}

/// Returns true inside [`with_trusted_encodings`] on this thread.
#[cfg(feature = "std")]
pub(crate) fn encodings_are_trusted() -> bool {
    TRUSTED.with(|trusted| trusted.get())
}

#[cfg(feature = "std")]
std::thread_local! {
    static TRUSTED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use group::GroupEncoding;

    use super::*;
    use rand_core::SeedableRng;

    use crate::value::{CommitmentSum, NoteValue, ValueCommitTrapdoor, ValueCommitment};

    #[test]
    fn invalid_commitments_are_deferred_inside_the_scope() {
        // (0, -1) has order 2.
        let order_two = jubjub::ExtendedPoint::from(jubjub::AffinePoint::from_raw_unchecked(
            bls12_381::Scalar::zero(),
            -bls12_381::Scalar::one(),
        ));
        let invalid = [
            [0xff; 32],
            jubjub::ExtendedPoint::identity().to_bytes(),
            order_two.to_bytes(),
        ];
        for bytes in invalid {
            assert!(bool::from(
                ValueCommitment::from_bytes_not_small_order(&bytes).is_none()
            ));
            let trusted =
                with_trusted_encodings(|| ValueCommitment::from_bytes_not_small_order(&bytes))
                    .unwrap();
            assert_eq!(trusted.to_bytes(), bytes);
            assert!(trusted.checked_point().is_none());
            assert!(std::panic::catch_unwind(|| CommitmentSum::zero() + &trusted).is_err());
        }
        assert!(!encodings_are_trusted());
    }

    #[test]
    fn trusted_commitments_match_decoded_commitments() {
        let mut rng = rand_xorshift::XorShiftRng::from_seed([7; 16]);
        let commitments: alloc::vec::Vec<_> = (0..4u64)
            .map(|value| {
                ValueCommitment::derive(
                    NoteValue::from_raw(value),
                    ValueCommitTrapdoor::random(&mut rng),
                )
                .to_bytes()
            })
            .collect();
        let decoded: alloc::vec::Vec<_> = commitments
            .iter()
            .map(|bytes| ValueCommitment::from_bytes_not_small_order(bytes).unwrap())
            .collect();
        let trusted: alloc::vec::Vec<_> = with_trusted_encodings(|| {
            commitments
                .iter()
                .map(|bytes| ValueCommitment::from_bytes_not_small_order(bytes).unwrap())
                .collect()
        });
        for (decoded, trusted) in decoded.iter().zip(&trusted) {
            assert_eq!(decoded.as_inner(), trusted.as_inner());
            assert_eq!(decoded.to_bytes(), trusted.to_bytes());
        }
        let bvk = |cvs: &[ValueCommitment]| -> [u8; 32] {
            cvs.iter()
                .fold(CommitmentSum::zero(), |sum, cv| sum + cv)
                .into_bvk(0i64)
                .into()
        };
        assert_eq!(bvk(&decoded), bvk(&trusted));
    }

    #[test]
    fn the_scope_ends_even_after_a_panic() {
        let result = std::panic::catch_unwind(|| with_trusted_encodings(|| panic!("inside")));
        assert!(result.is_err());
        assert!(!encodings_are_trusted());
    }
}
