use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::util::{ecdsa, schnorr, taproot};

pub fn ecdsa_to_schnorr(pk: &ecdsa::PublicKey) -> schnorr::PublicKey {
    schnorr::PublicKey::from_slice(&pk.to_bytes()[1..]).expect("Key conversion failure")
}

pub fn compute_merkle_root(
    leaf_hash: &taproot::TapLeafHash,
    control_block: &taproot::ControlBlock,
) -> taproot::TapBranchHash {
    taproot::TapBranchHash::from_inner(
        control_block
            .merkle_branch
            .as_inner()
            .iter()
            .fold(
                taproot::NodeInfo::new_hidden(
                    sha256::Hash::from_slice(leaf_hash.as_inner()).expect("Invalid TapLeafHash"),
                ),
                |acc, branch| {
                    taproot::NodeInfo::combine(acc, taproot::NodeInfo::new_hidden(*branch))
                        .expect("Invalid tree")
                },
            )
            .hash()
            .into_inner(),
    )
}
