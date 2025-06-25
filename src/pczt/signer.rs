use rand::{CryptoRng, RngCore};

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
}

/// Errors that can occur while signing an Orchard action in a PCZT.
#[derive(Debug)]
pub enum SignerError {
    /// The Signer role requires `alpha` to be set.
    MissingSpendAuthRandomizer,
    /// The provided `ask` does not own the action's spent note.
    WrongSpendAuthorizingKey,
}
