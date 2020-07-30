pub extern crate bitcoin;
extern crate log;
pub extern crate miniscript;
extern crate serde;
#[macro_use]
extern crate serde_json;

#[cfg(target_arch = "wasm32")]
#[macro_use]
extern crate async_trait;
#[macro_use]
extern crate magical_macros;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "electrum")]
pub extern crate electrum_client;
#[cfg(feature = "electrum")]
pub use electrum_client::client::Client;

#[cfg(feature = "esplora")]
pub extern crate reqwest;
#[cfg(feature = "esplora")]
pub use blockchain::esplora::EsploraBlockchain;

#[cfg(feature = "key-value-db")]
pub extern crate sled;

#[cfg(feature = "cli-utils")]
pub mod cli;

#[cfg(feature = "hardware-wallets")]
pub mod hardware_wallets;

#[macro_use]
pub mod error;
pub mod blockchain;
pub mod database;
pub mod descriptor;
pub mod psbt;
pub mod types;
pub mod wallet;

pub use wallet::{OfflineWallet, Wallet};
