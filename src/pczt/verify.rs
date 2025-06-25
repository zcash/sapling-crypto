use crate::{keys::FullViewingKey, value::ValueCommitment, Note, ViewingKey};

impl super::Spend {
    /// Verifies that the `cv` field is consistent with the note fields.
    ///
    /// Requires that the following optional fields are set:
    /// - `value`
    /// - `rcv`
    pub fn verify_cv(&self) -> Result<(), VerifyError> {
        let value = self.value.ok_or(VerifyError::MissingValue)?;
        let rcv = self
            .rcv
            .clone()
            .ok_or(VerifyError::MissingValueCommitTrapdoor)?;

        let cv_net = ValueCommitment::derive(value, rcv);
        if cv_net.to_bytes() == self.cv.to_bytes() {
            Ok(())
        } else {
            Err(VerifyError::InvalidValueCommitment)
        }
    }

    /// Returns the [`ViewingKey`] to use when validating this note.
    ///
    /// Handles dummy notes when the `value` field is set.
    fn vk_for_validation(
        &self,
        expected_fvk: Option<&FullViewingKey>,
    ) -> Result<ViewingKey, VerifyError> {
        let vk = self
            .proof_generation_key
            .as_ref()
            .map(|proof_generation_key| proof_generation_key.to_viewing_key());

        match (expected_fvk, vk, self.value.as_ref()) {
            (Some(expected_fvk), Some(vk), _)
                if vk.ak == expected_fvk.vk.ak && vk.nk == expected_fvk.vk.nk =>
            {
                Ok(vk)
            }
            // `expected_fvk` is ignored if the spent note is a dummy note.
            (Some(_), Some(vk), Some(value)) if value.inner() == 0 => Ok(vk),
            (Some(_), Some(_), _) => Err(VerifyError::MismatchedFullViewingKey),
            (Some(expected_fvk), None, _) => Ok(expected_fvk.vk.clone()),
            (None, Some(vk), _) => Ok(vk),
            (None, None, _) => Err(VerifyError::MissingProofGenerationKey),
        }
    }

    /// Verifies that the `nullifier` field is consistent with the note fields.
    ///
    /// Requires that the following optional fields are set:
    /// - `recipient`
    /// - `value`
    /// - `rseed`
    /// - `witness`
    ///
    /// In addition, at least one of the `proof_generation_key` field or `expected_fvk`
    /// must be provided.
    ///
    /// The provided [`FullViewingKey`] is ignored if the spent note is a dummy note.
    /// Otherwise, it will be checked against the `proof_generation_key` field (if both
    /// are set).
    pub fn verify_nullifier(
        &self,
        expected_fvk: Option<&FullViewingKey>,
    ) -> Result<(), VerifyError> {
        let vk = self.vk_for_validation(expected_fvk)?;

        let note = Note::from_parts(
            self.recipient.ok_or(VerifyError::MissingRecipient)?,
            self.value.ok_or(VerifyError::MissingValue)?,
            self.rseed.ok_or(VerifyError::MissingRandomSeed)?,
        );

        // We need both the note and the VK to verify the nullifier; we have everything
        // needed to also verify that the correct VK was provided (the nullifier check
        // itself only constrains `nk` within the VK).
        if vk.to_payment_address(*note.recipient().diversifier()) != Some(note.recipient()) {
            return Err(VerifyError::WrongFvkForNote);
        }

        let merkle_path = self.witness().as_ref().ok_or(VerifyError::MissingWitness)?;

        if note.nf(&vk.nk, merkle_path.position().into()) == self.nullifier {
            Ok(())
        } else {
            Err(VerifyError::InvalidNullifier)
        }
    }

    /// Verifies that the `rk` field is consistent with the given FVK.
    ///
    /// Requires that the following optional fields are set:
    /// - `alpha`
    ///
    /// The provided [`FullViewingKey`] is ignored if the spent note is a dummy note
    /// (which can only be determined if the `value` field is set). Otherwise, it will be
    /// checked against the `proof_generation_key` field (if set).
    pub fn verify_rk(&self, expected_fvk: Option<&FullViewingKey>) -> Result<(), VerifyError> {
        let vk = self.vk_for_validation(expected_fvk)?;

        let alpha = self
            .alpha
            .as_ref()
            .ok_or(VerifyError::MissingSpendAuthRandomizer)?;

        if vk.ak.randomize(alpha) == self.rk {
            Ok(())
        } else {
            Err(VerifyError::InvalidRandomizedVerificationKey)
        }
    }
}

impl super::Output {
    /// Verifies that the `cv` field is consistent with the note fields.
    ///
    /// Requires that the following optional fields are set:
    /// - `value`
    /// - `rcv`
    pub fn verify_cv(&self) -> Result<(), VerifyError> {
        let value = self.value.ok_or(VerifyError::MissingValue)?;
        let rcv = self
            .rcv
            .clone()
            .ok_or(VerifyError::MissingValueCommitTrapdoor)?;

        let cv_net = ValueCommitment::derive(value, rcv);
        if cv_net.to_bytes() == self.cv.to_bytes() {
            Ok(())
        } else {
            Err(VerifyError::InvalidValueCommitment)
        }
    }

    /// Verifies that the `cmu` field is consistent with the note fields.
    ///
    /// Requires that the following optional fields are set:
    /// - `recipient`
    /// - `value`
    /// - `rseed`
    pub fn verify_note_commitment(&self) -> Result<(), VerifyError> {
        let note = Note::from_parts(
            self.recipient.ok_or(VerifyError::MissingRecipient)?,
            self.value.ok_or(VerifyError::MissingValue)?,
            crate::Rseed::AfterZip212(self.rseed.ok_or(VerifyError::MissingRandomSeed)?),
        );

        if note.cmu() == self.cmu {
            Ok(())
        } else {
            Err(VerifyError::InvalidExtractedNoteCommitment)
        }
    }
}

/// Errors that can occur while verifying a PCZT bundle.
#[derive(Debug)]
pub enum VerifyError {
    /// The output note's components do not produce the expected `cmx`.
    InvalidExtractedNoteCommitment,
    /// The spent note's components do not produce the expected `nullifier`.
    InvalidNullifier,
    /// The Spend's FVK and `alpha` do not produce the expected `rk`.
    InvalidRandomizedVerificationKey,
    /// The action's `cv_net` does not match the provided note values and `rcv`.
    InvalidValueCommitment,
    /// The spend or output's `fvk` field does not match the provided FVK.
    MismatchedFullViewingKey,
    /// Dummy notes must have their `proof_generation_key` field set in order to be verified.
    MissingProofGenerationKey,
    /// `nullifier` verification requires `rseed` to be set.
    MissingRandomSeed,
    /// `nullifier` verification requires `recipient` to be set.
    MissingRecipient,
    /// `rk` verification requires `alpha` to be set.
    MissingSpendAuthRandomizer,
    /// Verification requires all `value` fields to be set.
    MissingValue,
    /// `cv_net` verification requires `rcv` to be set.
    MissingValueCommitTrapdoor,
    /// `nullifier` verification requires `witness` to be set.
    MissingWitness,
    /// The provided `fvk` does not own the spent note.
    WrongFvkForNote,
}
