#[cfg(test)]
pub mod test;

pub mod blake2s;
pub mod boolean;
pub mod ecc;
pub mod lookup;
pub mod multieq;
pub mod multipack;
pub mod num;
pub mod pedersen_hash;
pub mod sha256;
pub mod uint32;

pub mod sapling;
pub mod sprout;

use bellperson::SynthesisError;

// TODO: This should probably be removed and we
// should use existing helper methods on `Option`
// for mapping with an error.
/// This basically is just an extension to `Option`
/// which allows for a convenient mapping to an
/// error on `None`.
trait Assignment<T> {
    fn get(&self) -> Result<&T, SynthesisError>;
}

impl<T> Assignment<T> for Option<T> {
    fn get(&self) -> Result<&T, SynthesisError> {
        match *self {
            Some(ref v) => Ok(v),
            None => Err(SynthesisError::AssignmentMissing),
        }
    }
}
