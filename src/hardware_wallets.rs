use std::collections::HashSet;
use std::ops::Deref;

use bitcoin::consensus::encode::deserialize;
use bitcoin::util::bip32::{DerivationPath, Fingerprint};
use bitcoin::util::psbt::{Map, PartiallySignedTransaction};
use bitcoin::Address;

use hwi::types::HWIAddressType;
use hwi::HWIDevice;

use miniscript::signer::{Signer, SignerError};

use crate::error::Error;
use crate::wallet::utils::{AddressTypes, AddressViewer};

pub(crate) fn enumerate_devices() -> Result<Vec<HWIDeviceSigner>, Error> {
    Ok(hwi::interface::HWIDevice::enumerate()?
        .into_iter()
        .map(HWIDeviceSigner)
        .collect())
}

pub(crate) fn get_device(fingerprint: Fingerprint) -> Result<Option<HWIDeviceSigner>, Error> {
    Ok(enumerate_devices()?
        .into_iter()
        .find(|dev| dev.fingerprint == fingerprint))
}

#[derive(Debug)]
pub struct HWIDeviceSigner(HWIDevice);

impl Deref for HWIDeviceSigner {
    type Target = HWIDevice;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Signer for HWIDeviceSigner {
    fn sign(
        &self,
        psbt: &mut PartiallySignedTransaction,
        input_index: usize,
    ) -> Result<(), SignerError> {
        let signed = self
            .sign_tx(psbt, true)
            .map_err(|_| SignerError::UserCanceled)?;
        let signed = base64::decode(&signed.psbt).map_err(|_| SignerError::UserCanceled)?;
        let signed: PartiallySignedTransaction =
            deserialize(&signed).map_err(|_| SignerError::UserCanceled)?;

        psbt.inputs[input_index]
            .merge(signed.inputs[input_index].clone())
            .map_err(|_| SignerError::UserCanceled)?;

        Ok(())
    }
}

// impl AddressViewer for HWIDeviceSigner {
//     fn supported_types(&self) -> HashSet<AddressTypes> {
//         vec![AddressTypes::Pkh, AddressTypes::Wpkh, AddressTypes::ShWpkh].into_iter().collect()
//     }
//
//     fn show_addrss(&self, child: ChildNumber, address: &Address) -> bool {
//         let address_type = if address.script_pubkey().is_p2pkh() {
//             HWIAddressType::Pkh
//         } else if address.script_pubkey().is_p2sh() {
//             HWIAddressType::ShWpkh
//         } else if address.script_pubkey().is_v0_p2wpkh() {
//             HWIAddressType::Wpkh
//         } else {
//             return false;
//         };
//
//         match self.display_address_with_path(path, address_type, true) {
//             Ok(addr) => &addr.address == address,
//             Err(e) => {
//                 log::warn!("Error showing an address: {:?}", e);
//
//                 false
//             }
//         }
//     }
// }
