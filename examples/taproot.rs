// Bitcoin Dev Kit
// Written in 2021 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use std::str::FromStr;

use bdk::*;
use bdk::wallet::*;
use bdk::database::MemoryDatabase;
use bdk::bitcoin::{Network, self};
use bdk::bitcoin::consensus::encode::serialize_hex;

use bdk::electrum_client;
use bdk::blockchain::electrum::*;
use bdk::blockchain::esplora::*;
use bdk::blockchain::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // let client = electrum_client::Client::new("ssl://electrum.blockstream.info:60002")?;
    // let blockchain = ElectrumBlockchain::from(client);

    let blockchain = EsploraBlockchain::new("https://mempool.space/signet/api", 100);

    // let desc = "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm),pk(e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)})";
    let desc = "tr(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)";
    let wallet = Wallet::new(desc, None, Network::Signet, MemoryDatabase::new(), blockchain)?;
    println!("desc: {}", wallet.public_descriptor(KeychainKind::External)?.unwrap());

    wallet.sync(noop_progress(), None)?;

    let addr = wallet.get_address(AddressIndex::New).unwrap();
    println!("address: {}", addr);
    println!("script: {:?}", addr.script_pubkey());

    // let policy = wallet.policies(KeychainKind::External)?.unwrap();
    // dbg!(policy);

    let (mut psbt, details) = {
       let mut builder =  wallet.build_tx();
       builder
           .drain_to(addr.script_pubkey())
           .fee_rate(FeeRate::from_sat_per_vb(2.0));
       builder.finish()?
    };

    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
    dbg!(finalized);

    let tx = psbt.extract_tx();
    println!("{}", serialize_hex(&tx));

    wallet.broadcast(&tx)?;

    Ok(())
}
