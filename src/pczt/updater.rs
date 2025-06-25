use alloc::string::String;
use alloc::vec::Vec;

use crate::ProofGenerationKey;

use super::{Bundle, Output, Spend, Zip32Derivation};

impl Bundle {
    /// Updates the bundle with information provided in the given closure.
    pub fn update_with<F>(&mut self, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(Updater<'_>) -> Result<(), UpdaterError>,
    {
        f(Updater(self))
    }
}

/// An updater for a Sapling PCZT bundle.
pub struct Updater<'a>(&'a mut Bundle);

impl Updater<'_> {
    /// Provides read access to the bundle being updated.
    pub fn bundle(&self) -> &Bundle {
        self.0
    }

    /// Updates the spend at the given index with information provided in the given
    /// closure.
    pub fn update_spend_with<F>(&mut self, index: usize, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(SpendUpdater<'_>) -> Result<(), UpdaterError>,
    {
        f(SpendUpdater(
            self.0
                .spends
                .get_mut(index)
                .ok_or(UpdaterError::InvalidIndex)?,
        ))
    }

    /// Updates the output at the given index with information provided in the given
    /// closure.
    pub fn update_output_with<F>(&mut self, index: usize, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(OutputUpdater<'_>) -> Result<(), UpdaterError>,
    {
        f(OutputUpdater(
            self.0
                .outputs
                .get_mut(index)
                .ok_or(UpdaterError::InvalidIndex)?,
        ))
    }
}

/// An updater for a Sapling PCZT spend.
pub struct SpendUpdater<'a>(&'a mut Spend);

impl SpendUpdater<'_> {
    /// Sets the proof generation key for this spend.
    ///
    /// Returns an error if the proof generation key does not match the spend.
    pub fn set_proof_generation_key(
        &mut self,
        proof_generation_key: ProofGenerationKey,
    ) -> Result<(), UpdaterError> {
        // TODO: Verify that the proof generation key matches the spend, if possible.
        self.0.proof_generation_key = Some(proof_generation_key);
        Ok(())
    }

    /// Sets the ZIP 32 derivation path for the spent note's signing key.
    pub fn set_zip32_derivation(&mut self, derivation: Zip32Derivation) {
        self.0.zip32_derivation = Some(derivation);
    }

    /// Stores the given proprietary value at the given key.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }
}

/// An updater for a Sapling PCZT output.
pub struct OutputUpdater<'a>(&'a mut Output);

impl OutputUpdater<'_> {
    /// Sets the ZIP 32 derivation path for the new note's signing key.
    pub fn set_zip32_derivation(&mut self, derivation: Zip32Derivation) {
        self.0.zip32_derivation = Some(derivation);
    }

    /// Sets the user-facing address that the new note is being sent to.
    pub fn set_user_address(&mut self, user_address: String) {
        self.0.user_address = Some(user_address);
    }

    /// Stores the given proprietary value at the given key.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }
}

/// Errors that can occur while updating a Sapling bundle in a PCZT.
#[derive(Debug)]
pub enum UpdaterError {
    /// An out-of-bounds index was provided when looking up a spend or output.
    InvalidIndex,
    /// The provided `proof_generation_key` does not match the spend.
    WrongProofGenerationKey,
}
