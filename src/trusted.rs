//! Opt-in deferral of point decompression for encodings the caller already validated.

/// Runs `f` with point decompression deferred for keys and commitments parsed on this thread.
///
/// Only use it for encodings this library accepted before, such as transactions a node reads
/// back from its own verified state. Never parse network input inside it: the canonical-encoding
/// and small-order checks are skipped, and an invalid point panics when it is first used.
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
pub(crate) fn encodings_are_trusted() -> bool {
    #[cfg(feature = "std")]
    {
        TRUSTED.with(|trusted| trusted.get())
    }
    #[cfg(not(feature = "std"))]
    false
}

#[cfg(feature = "std")]
std::thread_local! {
    static TRUSTED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use group::{Group, GroupEncoding};

    use super::*;
    use rand_core::SeedableRng;

    use crate::value::{CommitmentSum, NoteValue, ValueCommitTrapdoor, ValueCommitment};

    #[test]
    fn invalid_commitments_are_rejected_unless_trusted() {
        for bytes in [[0xff; 32], jubjub::ExtendedPoint::identity().to_bytes()] {
            assert!(bool::from(
                ValueCommitment::from_bytes_not_small_order(&bytes).is_none()
            ));
            let trusted =
                with_trusted_encodings(|| ValueCommitment::from_bytes_not_small_order(&bytes));
            assert_eq!(trusted.unwrap().to_bytes(), bytes);
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
