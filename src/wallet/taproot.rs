use bitcoin::util::{ecdsa, schnorr};

pub fn ecdsa_to_schnorr(pk: &ecdsa::PublicKey) -> schnorr::PublicKey {
    schnorr::PublicKey::from_slice(&pk.to_bytes()[1..]).expect("Key conversion failure")
}
