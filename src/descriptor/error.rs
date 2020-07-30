#[derive(Debug)]
pub enum Error {
    Policy(crate::descriptor::policy::PolicyError),

    InvalidDescriptorCharacter(char),

    BIP32(bitcoin::util::bip32::Error),
    Base58(bitcoin::util::base58::Error),
    PK(bitcoin::util::key::Error),
    Miniscript(miniscript::Error),
    Hex(bitcoin::hashes::hex::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl_error!(bitcoin::util::bip32::Error, BIP32);
impl_error!(bitcoin::util::base58::Error, Base58);
impl_error!(bitcoin::util::key::Error, PK);
impl_error!(miniscript::Error, Miniscript);
impl_error!(bitcoin::hashes::hex::Error, Hex);
impl_error!(crate::descriptor::policy::PolicyError, Policy);
