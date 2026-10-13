//! Signs a message with a Sapling address and verifies the signature.
//!
//! ```sh
//! cargo run --release --example zip304 -- "hello"
//! ```

use std::env;

use rand::{rngs::StdRng, SeedableRng};
use sapling_crypto::{
    circuit::SpendParameters,
    keys::ExpandedSpendingKey,
    zip304::{sign_message, verify_message, Signature},
    Diversifier,
};

/// SLIP-44 coin type of Zcash mainnet.
const COIN_TYPE: u32 = 133;

fn main() {
    let message = env::args().nth(1).unwrap_or_else(|| "hello".into());

    let (spend_params, _) = wagyu_zcash_parameters::load_sapling_parameters();
    let params = SpendParameters::read(&spend_params[..], false).expect("valid parameters");
    let spend_vk = params.prepared_verifying_key();

    let expsk = ExpandedSpendingKey::from_spending_key(&[7; 32]).expect("valid key");
    let address = expsk
        .proof_generation_key()
        .to_viewing_key()
        .to_payment_address(Diversifier([0; 11]))
        .expect("valid diversifier");

    let signature = sign_message(
        StdRng::from_seed([0; 32]),
        &expsk,
        address,
        COIN_TYPE,
        message.as_bytes(),
        &params,
    );
    let encoded = signature.to_string();
    println!("message:   {message}");
    println!("signature: {encoded}");

    let parsed: Signature = encoded.parse().expect("round trip");
    let valid = verify_message(address, COIN_TYPE, message.as_bytes(), &parsed, &spend_vk);
    println!("verified:  {}", valid.is_ok());
}
