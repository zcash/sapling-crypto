use rand::{CryptoRng, RngCore};
use redjubjub::SpendAuth;

use crate::keys::SpendAuthorizingKey;

impl super::Spend {
    /// Signs the Sapling spend with the given spend authorizing key.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn sign<R: RngCore + CryptoRng>(
        &mut self,
        sighash: [u8; 32],
        ask: &SpendAuthorizingKey,
        rng: R,
    ) -> Result<(), SignerError> {
        let alpha = self.alpha.ok_or(SignerError::MissingSpendAuthRandomizer)?;

        let rsk = ask.randomize(&alpha);
        let rk = redjubjub::VerificationKey::from(&rsk);

        if self.rk == rk {
            self.spend_auth_sig = Some(rsk.sign(rng, &sighash));
            Ok(())
        } else {
            Err(SignerError::WrongSpendAuthorizingKey)
        }
    }

    /// Applies the given signature to the Sapling spend, if valid.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn apply_signature(
        &mut self,
        sighash: [u8; 32],
        signature: redjubjub::Signature<SpendAuth>,
    ) -> Result<(), SignerError> {
        if self.rk.verify(&sighash, &signature).is_ok() {
            self.spend_auth_sig = Some(signature);
            Ok(())
        } else {
            Err(SignerError::InvalidExternalSignature)
        }
    }
}

/// Errors that can occur while signing an Orchard action in a PCZT.
#[derive(Debug)]
pub enum SignerError {
    /// A provided external signature was not valid for the action's spend.
    InvalidExternalSignature,
    /// The Signer role requires `alpha` to be set.
    MissingSpendAuthRandomizer,
    /// The provided `ask` does not own the action's spent note.
    WrongSpendAuthorizingKey,
}
