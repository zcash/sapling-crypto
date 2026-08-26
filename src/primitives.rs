//! Primitives used in the Sapling protocol.

/// Bytes not a valid encoding for the field they were read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidPoint;

impl core::fmt::Display for InvalidPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not a valid encoding of a curve point for this field")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidPoint {}

/// Recovers a point a consensus rule requires canonical & not small order.
///
/// - One rule shared by every compressed point a bundle carries: `cv` in
///   [Spend][spenddesc] & [Output][outputdesc] descriptions, `rk`, `epk`
/// - Lands on affine = what both circuits take as public input; take coords from here
///   (promoting to [`jubjub::ExtendedPoint`] is free, the reverse costs an inversion)
///
/// # Errors
///
/// [`InvalidPoint`], for either rule. Not distinguished (both invalidate the description;
/// separating them tells a peer which rule it tripped).
///
/// [spenddesc]: https://zips.z.cash/protocol/protocol.pdf#spenddesc
/// [outputdesc]: https://zips.z.cash/protocol/protocol.pdf#outputdesc
pub(crate) fn decompress_not_small_order(
    bytes: &[u8; 32],
) -> Result<jubjub::AffinePoint, InvalidPoint> {
    let affine = Option::<jubjub::AffinePoint>::from(jubjub::AffinePoint::from_bytes(*bytes))
        .ok_or(InvalidPoint)?;

    if affine.is_small_order().into() {
        return Err(InvalidPoint);
    }

    Ok(affine)
}
