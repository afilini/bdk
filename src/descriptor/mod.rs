use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use bitcoin::hashes::hash160;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::{PublicKey, Script};

use miniscript::descriptor::DescriptorKey;
use miniscript::signer::SignersContainer;
pub use miniscript::{
    Descriptor, Legacy, Miniscript, MiniscriptKey, ScriptContext, Segwitv0, Terminal,
};

pub mod checksum;
pub mod error;
pub mod policy;

pub use self::checksum::get_checksum;
pub use self::policy::Policy;

use self::error::Error;

pub trait ExtractPolicy {
    fn extract_policy(
        &self,
        signers: Arc<SignersContainer<DescriptorKey>>,
    ) -> Result<Option<Policy>, Error>;
}

#[derive(Debug, Clone, Hash, PartialEq, PartialOrd, Eq, Ord, Default)]
struct DummyKey();

impl fmt::Display for DummyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyKey")
    }
}

impl std::str::FromStr for DummyKey {
    type Err = ();

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        Ok(DummyKey::default())
    }
}

impl miniscript::MiniscriptKey for DummyKey {
    type Hash = DummyKey;

    fn to_pubkeyhash(&self) -> DummyKey {
        DummyKey::default()
    }
}

pub trait DescriptorMeta {
    fn is_witness(&self) -> bool;
    fn get_hd_keypaths(
        &self,
        index: u32,
    ) -> Result<BTreeMap<PublicKey, (Fingerprint, DerivationPath)>, Error>;
    fn is_fixed(&self) -> bool;
}

pub trait DescriptorScripts {
    fn psbt_redeem_script(&self) -> Option<Script>;
    fn psbt_witness_script(&self) -> Option<Script>;
}

impl<T> DescriptorScripts for Descriptor<T>
where
    T: miniscript::MiniscriptKey + miniscript::ToPublicKey,
{
    fn psbt_redeem_script(&self) -> Option<Script> {
        match self {
            Descriptor::ShWpkh(_) => Some(self.witness_script()),
            Descriptor::ShWsh(ref script) => Some(script.encode().to_v0_p2wsh()),
            Descriptor::Sh(ref script) => Some(script.encode()),
            _ => None,
        }
    }

    fn psbt_witness_script(&self) -> Option<Script> {
        match self {
            Descriptor::Wsh(ref script) => Some(script.encode()),
            Descriptor::ShWsh(ref script) => Some(script.encode()),
            _ => None,
        }
    }
}

impl DescriptorMeta for Descriptor<DescriptorKey> {
    fn is_witness(&self) -> bool {
        match self {
            Descriptor::Bare(_) | Descriptor::Pk(_) | Descriptor::Pkh(_) | Descriptor::Sh(_) => {
                false
            }
            Descriptor::Wpkh(_)
            | Descriptor::ShWpkh(_)
            | Descriptor::Wsh(_)
            | Descriptor::ShWsh(_) => true,
        }
    }

    fn get_hd_keypaths(
        &self,
        index: u32,
    ) -> Result<BTreeMap<PublicKey, (Fingerprint, DerivationPath)>, Error> {
        let mut answer = BTreeMap::new();

        let translatefpk = |key: &DescriptorKey| -> Result<_, Error> {
            match key {
                DescriptorKey::PubKey(_) => {}
                DescriptorKey::XPub(xpub) => {
                    let derive_path = if xpub.is_wildcard {
                        xpub.derivation_path
                            .into_iter()
                            .chain([ChildNumber::from_normal_idx(index)?].iter())
                            .cloned()
                            .collect()
                    } else {
                        xpub.derivation_path.clone()
                    };

                    let derived_pubkey = xpub.xkey.derive_pub(&Secp256k1::new(), &derive_path)?;

                    answer.insert(
                        derived_pubkey.public_key,
                        (
                            xpub.root_fingerprint(),
                            xpub.full_path(&[ChildNumber::from_normal_idx(index)?]),
                        ),
                    );
                }
            }

            Ok(DummyKey::default())
        };
        let translatefpkh = |_: &hash160::Hash| -> Result<_, Error> { Ok(DummyKey::default()) };

        self.translate_pk(translatefpk, translatefpkh).unwrap();

        Ok(answer)
    }

    fn is_fixed(&self) -> bool {
        let mut found_wildcard = false;

        let translatefpk = |key: &DescriptorKey| -> Result<_, Error> {
            match key {
                DescriptorKey::PubKey(_) => {}
                DescriptorKey::XPub(xpub) => {
                    if xpub.is_wildcard {
                        found_wildcard = true;
                    }
                }
            }

            Ok(DummyKey::default())
        };
        let translatefpkh = |_: &hash160::Hash| -> Result<_, Error> { Ok(DummyKey::default()) };

        self.translate_pk(translatefpk, translatefpkh).unwrap();

        !found_wildcard
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::hashes::hex::FromHex;
    use bitcoin::{Network, PublicKey};

    use crate::descriptor::*;

    macro_rules! hex_fingerprint {
        ($hex:expr) => {
            Fingerprint::from_hex($hex).unwrap()
        };
    }

    macro_rules! hex_pubkey {
        ($hex:expr) => {
            PublicKey::from_str($hex).unwrap()
        };
    }

    macro_rules! deriv_path {
        ($str:expr) => {
            DerivationPath::from_str($str).unwrap()
        };

        () => {
            DerivationPath::from(vec![])
        };
    }

    #[test]
    fn test_descriptor_parse_wif() {
        let string = "pkh(cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy)";
        let desc = ExtendedDescriptor::from_str(string).unwrap();
        assert!(desc.is_fixed());
        assert_eq!(
            desc.derive(0)
                .unwrap()
                .address(Network::Testnet)
                .unwrap()
                .to_string(),
            "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx"
        );
        assert_eq!(
            desc.derive(42)
                .unwrap()
                .address(Network::Testnet)
                .unwrap()
                .to_string(),
            "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx"
        );
        assert_eq!(
            desc.get_secret_keys().into_iter().collect::<Vec<_>>().len(),
            1
        );
    }

    #[test]
    fn test_descriptor_parse_pubkey() {
        let string = "pkh(039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef)";
        let desc = ExtendedDescriptor::from_str(string).unwrap();
        assert!(desc.is_fixed());
        assert_eq!(
            desc.derive(0)
                .unwrap()
                .address(Network::Testnet)
                .unwrap()
                .to_string(),
            "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx"
        );
        assert_eq!(
            desc.derive(42)
                .unwrap()
                .address(Network::Testnet)
                .unwrap()
                .to_string(),
            "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx"
        );
        assert_eq!(
            desc.get_secret_keys().into_iter().collect::<Vec<_>>().len(),
            0
        );
    }

    #[test]
    fn test_descriptor_parse_xpub() {
        let string = "pkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/*)";
        let desc = ExtendedDescriptor::from_str(string).unwrap();
        assert!(!desc.is_fixed());
        assert_eq!(
            desc.derive(0)
                .unwrap()
                .address(Network::Testnet)
                .unwrap()
                .to_string(),
            "mxbXpnVkwARGtYXk5yeGYf59bGWuPpdE4X"
        );
        assert_eq!(
            desc.derive(42)
                .unwrap()
                .address(Network::Testnet)
                .unwrap()
                .to_string(),
            "mhtuS1QaEV4HPcK4bWk4Wvpd64SUjiC5Zt"
        );
        assert_eq!(desc.get_xprv().into_iter().collect::<Vec<_>>().len(), 0);
    }

    #[test]
    #[should_panic(expected = "KeyParsingError")]
    fn test_descriptor_parse_fail() {
        let string = "pkh(this_is_not_a_valid_key)";
        ExtendedDescriptor::from_str(string).unwrap();
    }

    #[test]
    fn test_descriptor_hd_keypaths() {
        let string = "pkh(tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/*)";
        let desc = ExtendedDescriptor::from_str(string).unwrap();
        let keypaths = desc.get_hd_keypaths(0).unwrap();
        assert!(keypaths.contains_key(&hex_pubkey!(
            "025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b6"
        )));
        assert_eq!(
            keypaths.get(&hex_pubkey!(
                "025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b6"
            )),
            Some(&(hex_fingerprint!("31a507b8"), deriv_path!("m/0")))
        )
    }
}
