use rand::{CryptoRng, RngCore};

use crate::{
    prover::{OutputProver, SpendProver},
    Note, Rseed,
};

impl super::Bundle {
    /// Adds a proof to this PCZT bundle.
    pub fn create_proofs<S, O, R: RngCore + CryptoRng>(
        &mut self,
        spend_prover: &S,
        output_prover: &O,
        mut rng: R,
    ) -> Result<(), ProverError>
    where
        S: SpendProver,
        O: OutputProver,
    {
        for spend in &mut self.spends {
            let proof_generation_key = spend
                .proof_generation_key
                .clone()
                .ok_or(ProverError::MissingProofGenerationKey)?;

            let note = Note::from_parts(
                spend.recipient.ok_or(ProverError::MissingRecipient)?,
                spend.value.ok_or(ProverError::MissingValue)?,
                spend.rseed.ok_or(ProverError::MissingRandomSeed)?,
            );

            let alpha = spend.alpha.ok_or(ProverError::MissingSpendAuthRandomizer)?;

            let rcv = spend
                .rcv
                .clone()
                .ok_or(ProverError::MissingValueCommitTrapdoor)?;

            let merkle_path = spend.witness.clone().ok_or(ProverError::MissingWitness)?;

            let circuit = S::prepare_circuit(
                proof_generation_key,
                *note.recipient().diversifier(),
                *note.rseed(),
                note.value(),
                alpha,
                rcv,
                self.anchor.inner(),
                merkle_path,
            )
            .ok_or(ProverError::InvalidDiversifier)?;

            let proof = spend_prover.create_proof(circuit, &mut rng);
            spend.zkproof = Some(S::encode_proof(proof));
        }

        for output in &mut self.outputs {
            let recipient = output.recipient.ok_or(ProverError::MissingRecipient)?;
            let value = output.value.ok_or(ProverError::MissingValue)?;

            let note = Note::from_parts(
                recipient,
                value,
                output
                    .rseed
                    .map(Rseed::AfterZip212)
                    .ok_or(ProverError::MissingRandomSeed)?,
            );

            let esk = note.generate_or_derive_esk(&mut rng);
            let rcm = note.rcm();

            let rcv = output
                .rcv
                .clone()
                .ok_or(ProverError::MissingValueCommitTrapdoor)?;

            let circuit = O::prepare_circuit(&esk, recipient, rcm, value, rcv);
            let proof = output_prover.create_proof(circuit, &mut rng);
            output.zkproof = Some(O::encode_proof(proof));
        }

        Ok(())
    }
}

/// Errors that can occur while creating Sapling proofs for a PCZT.
#[derive(Debug)]
pub enum ProverError {
    InvalidDiversifier,
    /// The Prover role requires all `proof_generation_key` fields to be set.
    MissingProofGenerationKey,
    /// The Prover role requires all `rseed` fields to be set.
    MissingRandomSeed,
    /// The Prover role requires all `recipient` fields to be set.
    MissingRecipient,
    /// The Prover role requires all `alpha` fields to be set.
    MissingSpendAuthRandomizer,
    /// The Prover role requires all `value` fields to be set.
    MissingValue,
    /// The Prover role requires all `rcv` fields to be set.
    MissingValueCommitTrapdoor,
    /// The Prover role requires all `witness` fields to be set.
    MissingWitness,
}
