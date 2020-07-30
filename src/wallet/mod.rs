use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::ops::DerefMut;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode::serialize;
use bitcoin::util::bip32::ChildNumber;
use bitcoin::util::psbt::PartiallySignedTransaction as PSBT;
use bitcoin::{Address, Network, OutPoint, Script, SigHashType, Transaction, TxIn, TxOut, Txid};

use miniscript::descriptor::{DescriptorKey, DescriptorKeyWithSecrets};
use miniscript::signer::{DescriptorWithSigners, PSBTSigningContext, SignersContainer};
use miniscript::Descriptor;

#[allow(unused_imports)]
use log::{debug, error, info, trace};

pub mod utils;

use self::utils::{AddressViewer, After, IsDust, Older};
use crate::blockchain::{noop_progress, Blockchain, OfflineBlockchain, OnlineBlockchain};
use crate::database::{BatchDatabase, BatchOperations, DatabaseUtils};
use crate::descriptor::{get_checksum, DescriptorMeta, DescriptorScripts, ExtractPolicy, Policy};
use crate::error::Error;
use crate::psbt::PSBTUtils;
use crate::types::*;

#[cfg(feature = "hardware-wallets")]
use crate::hardware_wallets;

pub type OfflineWallet<D> = Wallet<OfflineBlockchain, D>;

pub struct Wallet<B: Blockchain, D: BatchDatabase> {
    descriptor: Descriptor<DescriptorKey>,
    change_descriptor: Option<Descriptor<DescriptorKey>>,
    signers: Arc<SignersContainer<DescriptorKey>>,

    network: Network,

    current_height: Option<u32>,

    address_viewers: Vec<Box<dyn AddressViewer>>,

    client: RefCell<B>,
    database: RefCell<D>,
}

// offline actions, always available
impl<B, D> Wallet<B, D>
where
    B: Blockchain,
    D: BatchDatabase,
{
    pub fn new_offline(
        descriptor: &str,
        change_descriptor: Option<&str>,
        network: Network,
        mut database: D,
    ) -> Result<Self, Error> {
        database.check_descriptor_checksum(
            ScriptType::External,
            get_checksum(descriptor)?.as_bytes(),
        )?;
        let DescriptorWithSigners {
            descriptor,
            mut signers,
        } = DescriptorWithSigners::<DescriptorKeyWithSecrets>::from_str(descriptor)?;

        let change_descriptor = match change_descriptor {
            Some(desc) => {
                database.check_descriptor_checksum(
                    ScriptType::Internal,
                    get_checksum(desc)?.as_bytes(),
                )?;

                let DescriptorWithSigners {
                    descriptor: change_descriptor,
                    signers: change_signers,
                } = DescriptorWithSigners::<DescriptorKeyWithSecrets>::from_str(desc)?;
                signers.merge(change_signers).unwrap();

                Some(change_descriptor)
            }
            None => None,
        };

        let mut address_viewers = vec![];

        #[cfg(feature = "hardware-wallets")]
        for (_, (fingerprint, _)) in descriptor.get_hd_keypaths(0)?.into_iter().chain(
            change_descriptor
                .as_ref()
                .map(|d| d.get_hd_keypaths(0))
                .transpose()?
                .unwrap_or(BTreeMap::new()),
        ) {
            if signers.find(fingerprint.into()).is_none() {
                if let Some(device) = hardware_wallets::get_device(fingerprint)? {
                    info!("Found HWI device for: {}", device.fingerprint);

                    signers.add_external(fingerprint.into(), Box::new(device));
                }
            }
        }

        Ok(Wallet {
            descriptor,
            change_descriptor,
            signers: Arc::new(signers),

            network,

            current_height: None,

            address_viewers,

            client: RefCell::new(B::offline()),
            database: RefCell::new(database),
        })
    }

    pub fn get_new_address(&self) -> Result<Address, Error> {
        let index = self
            .database
            .borrow_mut()
            .increment_last_index(ScriptType::External)?;
        // TODO: refill the address pool if index is close to the last cached addr

        let child_number = ChildNumber::from_normal_idx(index)?;

        let address = self
            .descriptor
            .derive(&[child_number])
            .address(self.network)
            .ok_or(Error::ScriptDoesntHaveAddressForm)?;

        if !self
            .address_viewers
            .iter()
            .all(|viewer| viewer.show_address(child_number, &address))
        {
            Err(Error::UserRejectedAddress)
        } else {
            Ok(address)
        }
    }

    pub fn is_mine(&self, script: &Script) -> Result<bool, Error> {
        self.database.borrow().is_mine(script)
    }

    pub fn list_unspent(&self) -> Result<Vec<UTXO>, Error> {
        self.database.borrow().iter_utxos()
    }

    pub fn list_transactions(&self, include_raw: bool) -> Result<Vec<TransactionDetails>, Error> {
        self.database.borrow().iter_txs(include_raw)
    }

    pub fn get_balance(&self) -> Result<u64, Error> {
        Ok(self
            .list_unspent()?
            .iter()
            .fold(0, |sum, i| sum + i.txout.value))
    }

    // TODO: add a flag to ignore change in coin selection
    pub fn create_tx(
        &self,
        addressees: Vec<(Address, u64)>,
        send_all: bool,
        fee_perkb: f32,
        policy_path: Option<BTreeMap<String, Vec<usize>>>,
        utxos: Option<Vec<OutPoint>>,
        unspendable: Option<Vec<OutPoint>>,
    ) -> Result<(PSBT, TransactionDetails), Error> {
        let policy = self
            .descriptor
            .extract_policy(Arc::clone(&self.signers))?
            .unwrap();
        if policy.requires_path() && policy_path.is_none() {
            return Err(Error::SpendingPolicyRequired);
        }
        let requirements = policy.get_requirements(&policy_path.unwrap_or(BTreeMap::new()))?;
        debug!("requirements: {:?}", requirements);

        let mut tx = Transaction {
            version: 2,
            lock_time: requirements.timelock.unwrap_or(0),
            input: vec![],
            output: vec![],
        };

        let fee_rate = fee_perkb * 100_000.0;
        if send_all && addressees.len() != 1 {
            return Err(Error::SendAllMultipleOutputs);
        }

        // we keep it as a float while we accumulate it, and only round it at the end
        let mut fee_val: f32 = 0.0;
        let mut outgoing: u64 = 0;
        let mut received: u64 = 0;

        let calc_fee_bytes = |wu| (wu as f32) * fee_rate / 4.0;
        fee_val += calc_fee_bytes(tx.get_weight());

        for (index, (address, satoshi)) in addressees.iter().enumerate() {
            let value = match send_all {
                true => 0,
                false if satoshi.is_dust() => return Err(Error::OutputBelowDustLimit(index)),
                false => *satoshi,
            };

            // TODO: check address network
            if self.is_mine(&address.script_pubkey())? {
                received += value;
            }

            let new_out = TxOut {
                script_pubkey: address.script_pubkey(),
                value,
            };
            fee_val += calc_fee_bytes(serialize(&new_out).len() * 4);

            tx.output.push(new_out);

            outgoing += value;
        }

        // TODO: assumes same weight to spend external and internal
        let input_witness_weight = self.descriptor.max_satisfaction_weight();

        let (available_utxos, use_all_utxos) =
            self.get_available_utxos(&utxos, &unspendable, send_all)?;
        let (mut inputs, paths, selected_amount, mut fee_val) = self.coin_select(
            available_utxos,
            use_all_utxos,
            fee_rate,
            outgoing,
            input_witness_weight,
            fee_val,
        )?;
        let n_sequence = if let Some(csv) = requirements.csv {
            csv
        } else if requirements.timelock.is_some() {
            0xFFFFFFFE
        } else {
            0xFFFFFFFF
        };

        inputs.iter_mut().for_each(|i| i.sequence = n_sequence);
        tx.input.append(&mut inputs);

        // prepare the change output
        let change_output = match send_all {
            true => None,
            false => {
                let change_script = self.get_change_address()?;
                let change_output = TxOut {
                    script_pubkey: change_script,
                    value: 0,
                };

                // take the change into account for fees
                fee_val += calc_fee_bytes(serialize(&change_output).len() * 4);
                Some(change_output)
            }
        };

        let change_val = selected_amount - outgoing - (fee_val.ceil() as u64);
        if !send_all && !change_val.is_dust() {
            let mut change_output = change_output.unwrap();
            change_output.value = change_val;
            received += change_val;

            tx.output.push(change_output);
        } else if send_all && !change_val.is_dust() {
            // set the outgoing value to whatever we've put in
            outgoing = selected_amount;
            // there's only one output, send everything to it
            tx.output[0].value = change_val;

            // send_all to our address
            if self.is_mine(&tx.output[0].script_pubkey)? {
                received = change_val;
            }
        } else if send_all {
            // send_all but the only output would be below dust limit
            return Err(Error::InsufficientFunds); // TODO: or OutputBelowDustLimit?
        }

        // TODO: shuffle the outputs

        let txid = tx.txid();
        let mut psbt = PSBT::from_unsigned_tx(tx)?;

        // add metadata for the inputs
        for ((psbt_input, (script_type, child)), input) in psbt
            .inputs
            .iter_mut()
            .zip(paths.into_iter())
            .zip(psbt.global.unsigned_tx.input.iter())
        {
            let desc = self.get_descriptor_for_script_type(script_type);
            psbt_input.hd_keypaths = desc.get_hd_keypaths(child).unwrap();
            let derived_descriptor = desc.derive(&[ChildNumber::from_normal_idx(child)?]);

            // TODO: figure out what do redeem_script and witness_script mean
            psbt_input.redeem_script = derived_descriptor.psbt_redeem_script();
            psbt_input.witness_script = derived_descriptor.psbt_witness_script();

            let prev_output = input.previous_output;
            let prev_tx = self
                .database
                .borrow()
                .get_raw_tx(&prev_output.txid)?
                .unwrap(); // TODO: remove unwrap

            if derived_descriptor.is_witness() {
                psbt_input.witness_utxo = Some(prev_tx.output[prev_output.vout as usize].clone());
            } else {
                psbt_input.non_witness_utxo = Some(prev_tx);
            };

            // we always sign with SIGHASH_ALL
            psbt_input.sighash_type = Some(SigHashType::All);
        }

        for (psbt_output, tx_output) in psbt
            .outputs
            .iter_mut()
            .zip(psbt.global.unsigned_tx.output.iter())
        {
            if let Some((script_type, child)) = self
                .database
                .borrow()
                .get_path_from_script_pubkey(&tx_output.script_pubkey)?
            {
                let desc = self.get_descriptor_for_script_type(script_type);
                psbt_output.hd_keypaths = desc.get_hd_keypaths(child)?;
            }
        }

        let transaction_details = TransactionDetails {
            transaction: None,
            txid,
            timestamp: Self::get_timestamp(),
            received,
            sent: outgoing,
            height: None,
        };

        Ok((psbt, transaction_details))
    }

    pub fn sign(&self, mut psbt: PSBT, assume_height: Option<u32>) -> Result<(PSBT, bool), Error> {
        // this helps us doing our job later
        self.add_hd_keypaths(&mut psbt)?;

        let mut tx = psbt.global.unsigned_tx.clone();

        for (n, input) in tx.input.iter_mut().enumerate() {
            let desc = match psbt
                .get_utxo_for(n)
                .map(|txout| self.get_descriptor_for_txout(&txout))
                .transpose()?
                .flatten()
            {
                Some(desc) => desc,
                None => {
                    // TODO: try to determine this from the paths in `hd_keypaths`.

                    // Try with both. Inside here with the internal descriptor (if present), then
                    // return the external and try with it a few lines down
                    if let Some(change_descriptor) = self.change_descriptor.as_ref() {
                        let signing_ctx = PSBTSigningContext::new(&mut psbt, n, &self.signers);
                        if let Err(e) = change_descriptor.satisfy(input, signing_ctx) {
                            info!("Couldn't satisfy input #{} : {:?}", n, e);
                        }
                    }

                    &self.descriptor
                }
            };

            let signing_ctx = PSBTSigningContext::new(&mut psbt, n, &self.signers);
            if let Err(e) = desc.satisfy(input, signing_ctx) {
                info!("Couldn't satisfy input #{} : {:?}", n, e);
            }
        }

        // attempt to finalize
        let finalized = self.finalize_psbt(&mut psbt, assume_height)?;

        Ok((psbt, finalized))
    }

    pub fn policies(&self, script_type: ScriptType) -> Result<Option<Policy>, Error> {
        match (script_type, self.change_descriptor.as_ref()) {
            (ScriptType::External, _) => {
                Ok(self.descriptor.extract_policy(Arc::clone(&self.signers))?)
            }
            (ScriptType::Internal, None) => Ok(None),
            (ScriptType::Internal, Some(desc)) => {
                Ok(desc.extract_policy(Arc::clone(&self.signers))?)
            }
        }
    }

    pub fn public_descriptor(
        &self,
        script_type: ScriptType,
    ) -> Result<Option<&Descriptor<DescriptorKey>>, Error> {
        match (script_type, self.change_descriptor.as_ref()) {
            (ScriptType::External, _) => Ok(Some(&self.descriptor)),
            (ScriptType::Internal, None) => Ok(None),
            (ScriptType::Internal, Some(desc)) => Ok(Some(desc)),
        }
    }

    pub fn finalize_psbt(
        &self,
        psbt: &mut PSBT,
        assume_height: Option<u32>,
    ) -> Result<bool, Error> {
        let mut tx = psbt.global.unsigned_tx.clone();

        for (n, input) in tx.input.iter_mut().enumerate() {
            // if the height is None in the database it means it's still unconfirmed, so consider
            // that as a very high value
            let create_height = self
                .database
                .borrow()
                .get_tx(&input.previous_output.txid, false)?
                .and_then(|tx| Some(tx.height.unwrap_or(std::u32::MAX)));
            // TODO: keep current_height updated when we will sync headers
            let current_height = assume_height.or(self.current_height);

            debug!(
                "Input #{} - {}, using `create_height` = {:?}, `current_height` = {:?}",
                n, input.previous_output, create_height, current_height
            );

            let desc = match psbt
                .get_utxo_for(n)
                .map(|txout| self.get_descriptor_for_txout(&txout))
                .transpose()?
                .flatten()
            {
                Some(desc) => desc,
                None => {
                    // TODO: try to determine this from the paths in `hd_keypaths`

                    // Try with both. Inside here with the internal descriptor (if present), then
                    // return the external and try with it a few lines down
                    if let Some(change_descriptor) = self.change_descriptor.as_ref() {
                        match change_descriptor.satisfy(
                            input,
                            (
                                psbt.inputs[n].clone(),
                                After::new(current_height, false),
                                Older::new(current_height, create_height, false),
                            ),
                        ) {
                            Ok(_) => continue,
                            Err(_) => {} // ignore the error and try later with the other one
                        }
                    }

                    &self.descriptor
                }
            };

            match desc.satisfy(
                input,
                (
                    psbt.inputs[n].clone(),
                    After::new(current_height, false),
                    Older::new(current_height, create_height, false),
                ),
            ) {
                Ok(_) => continue,
                Err(e) => {
                    debug!("satisfy error {:?} for input {}", e, n);
                    return Ok(false);
                }
            }
        }

        // consume tx to extract its input's script_sig and witnesses and move them into the psbt
        for (input, psbt_input) in tx.input.into_iter().zip(psbt.inputs.iter_mut()) {
            psbt_input.final_script_sig = Some(input.script_sig);
            psbt_input.final_script_witness = Some(input.witness);
        }

        Ok(true)
    }

    // Internals

    #[cfg(not(target_arch = "wasm32"))]
    fn get_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[cfg(target_arch = "wasm32")]
    fn get_timestamp() -> u64 {
        0
    }

    fn get_descriptor_for_script_type(
        &self,
        script_type: ScriptType,
    ) -> &Descriptor<DescriptorKey> {
        let desc = match script_type {
            ScriptType::External => &self.descriptor,
            ScriptType::Internal => &self.change_descriptor.as_ref().unwrap_or(&self.descriptor),
        };

        desc
    }

    fn get_descriptor_for_txout(
        &self,
        txout: &TxOut,
    ) -> Result<Option<&Descriptor<DescriptorKey>>, Error> {
        Ok(self
            .database
            .borrow()
            .get_path_from_script_pubkey(&txout.script_pubkey)?
            .map(|(script_type, _)| self.get_descriptor_for_script_type(script_type)))
    }

    fn get_change_address(&self) -> Result<Script, Error> {
        let (desc, script_type) = if self.change_descriptor.is_none() {
            (&self.descriptor, ScriptType::External)
        } else {
            (
                self.change_descriptor.as_ref().unwrap(),
                ScriptType::Internal,
            )
        };

        // TODO: refill the address pool if index is close to the last cached addr
        let index = self
            .database
            .borrow_mut()
            .increment_last_index(script_type)?;

        Ok(desc
            .derive(&[ChildNumber::from_normal_idx(index)?])
            .script_pubkey())
    }

    fn get_available_utxos(
        &self,
        utxo: &Option<Vec<OutPoint>>,
        unspendable: &Option<Vec<OutPoint>>,
        send_all: bool,
    ) -> Result<(Vec<UTXO>, bool), Error> {
        // TODO: should we consider unconfirmed received rbf txs as "unspendable" too by default?
        let unspendable_set = match unspendable {
            None => HashSet::new(),
            Some(vec) => vec.into_iter().collect(),
        };

        match utxo {
            // with manual coin selection we always want to spend all the selected utxos, no matter
            // what (even if they are marked as unspendable)
            Some(raw_utxos) => {
                // TODO: unwrap to remove
                let full_utxos: Vec<_> = raw_utxos
                    .iter()
                    .map(|u| self.database.borrow().get_utxo(&u).unwrap())
                    .collect();
                if !full_utxos.iter().all(|u| u.is_some()) {
                    return Err(Error::UnknownUTXO);
                }

                Ok((full_utxos.into_iter().map(|x| x.unwrap()).collect(), true))
            }
            // otherwise limit ourselves to the spendable utxos and the `send_all` setting
            None => Ok((
                self.list_unspent()?
                    .into_iter()
                    .filter(|u| !unspendable_set.contains(&u.outpoint))
                    .collect(),
                send_all,
            )),
        }
    }

    fn coin_select(
        &self,
        mut utxos: Vec<UTXO>,
        use_all_utxos: bool,
        fee_rate: f32,
        outgoing: u64,
        input_witness_weight: usize,
        mut fee_val: f32,
    ) -> Result<(Vec<TxIn>, Vec<(ScriptType, u32)>, u64, f32), Error> {
        let mut answer = Vec::new();
        let mut deriv_indexes = Vec::new();
        let calc_fee_bytes = |wu| (wu as f32) * fee_rate / 4.0;

        debug!(
            "coin select: outgoing = `{}`, fee_val = `{}`, fee_rate = `{}`",
            outgoing, fee_val, fee_rate
        );

        // sort so that we pick them starting from the larger. TODO: proper coin selection
        utxos.sort_by(|a, b| a.txout.value.partial_cmp(&b.txout.value).unwrap());

        let mut selected_amount: u64 = 0;
        while use_all_utxos || selected_amount < outgoing + (fee_val.ceil() as u64) {
            let utxo = match utxos.pop() {
                Some(utxo) => utxo,
                None if selected_amount < outgoing + (fee_val.ceil() as u64) => {
                    return Err(Error::InsufficientFunds)
                }
                None if use_all_utxos => break,
                None => return Err(Error::InsufficientFunds),
            };

            let new_in = TxIn {
                previous_output: utxo.outpoint,
                script_sig: Script::default(),
                sequence: 0xFFFFFFFD, // TODO: change according to rbf/csv
                witness: vec![],
            };
            fee_val += calc_fee_bytes(serialize(&new_in).len() * 4 + input_witness_weight);
            debug!("coin select new fee_val = `{}`", fee_val);

            answer.push(new_in);
            selected_amount += utxo.txout.value;

            let child = self
                .database
                .borrow()
                .get_path_from_script_pubkey(&utxo.txout.script_pubkey)?
                .unwrap(); // TODO: remove unrwap
            deriv_indexes.push(child);
        }

        Ok((answer, deriv_indexes, selected_amount, fee_val))
    }

    fn add_hd_keypaths(&self, psbt: &mut PSBT) -> Result<(), Error> {
        let mut input_utxos = Vec::with_capacity(psbt.inputs.len());
        for n in 0..psbt.inputs.len() {
            input_utxos.push(psbt.get_utxo_for(n).clone());
        }

        // try to add hd_keypaths if we've already seen the output
        for (psbt_input, out) in psbt.inputs.iter_mut().zip(input_utxos.iter()) {
            debug!("searching hd_keypaths for out: {:?}", out);

            if let Some(out) = out {
                let option_path = self
                    .database
                    .borrow()
                    .get_path_from_script_pubkey(&out.script_pubkey)?;

                debug!("found descriptor path {:?}", option_path);

                let (script_type, child) = match option_path {
                    None => continue,
                    Some((script_type, child)) => (script_type, child),
                };

                // merge hd_keypaths
                let desc = self.get_descriptor_for_script_type(script_type);
                let mut hd_keypaths = desc.get_hd_keypaths(child)?;
                psbt_input.hd_keypaths.append(&mut hd_keypaths);
            }
        }

        Ok(())
    }
}

impl<B, D> Wallet<B, D>
where
    B: OnlineBlockchain,
    D: BatchDatabase,
{
    #[maybe_async]
    pub fn new(
        descriptor: &str,
        change_descriptor: Option<&str>,
        network: Network,
        database: D,
        mut client: B,
    ) -> Result<Self, Error> {
        let mut wallet = Self::new_offline(descriptor, change_descriptor, network, database)?;
        wallet.current_height = Some(maybe_await!(client.get_height())? as u32);
        wallet.client = RefCell::new(client);

        Ok(wallet)
    }

    #[maybe_async]
    pub fn sync(
        &self,
        max_address: Option<u32>,
        _batch_query_size: Option<usize>,
    ) -> Result<(), Error> {
        debug!("begin sync...");
        // TODO: consider taking an RwLock as writere here to prevent other "read-only" calls to
        // break because the db is in an inconsistent state

        let max_address = if self.descriptor.is_fixed() {
            0
        } else {
            max_address.unwrap_or(100)
        };

        // TODO:
        // let batch_query_size = batch_query_size.unwrap_or(20);

        let last_addr = self
            .database
            .borrow()
            .get_script_pubkey_from_path(ScriptType::External, max_address)?;

        // cache a few of our addresses
        if last_addr.is_none() {
            let mut address_batch = self.database.borrow().begin_batch();
            #[cfg(not(target_arch = "wasm32"))]
            let start = Instant::now();

            for i in 0..=max_address {
                let derived = self
                    .descriptor
                    .derive(&[ChildNumber::from_normal_idx(i).unwrap()]);

                address_batch.set_script_pubkey(
                    &derived.script_pubkey(),
                    ScriptType::External,
                    i,
                )?;
            }
            if self.change_descriptor.is_some() {
                for i in 0..=max_address {
                    let derived = self
                        .change_descriptor
                        .as_ref()
                        .unwrap()
                        .derive(&[ChildNumber::from_normal_idx(i).unwrap()]);

                    address_batch.set_script_pubkey(
                        &derived.script_pubkey(),
                        ScriptType::Internal,
                        i,
                    )?;
                }
            }

            #[cfg(not(target_arch = "wasm32"))]
            info!(
                "derivation of {} addresses, took {} ms",
                max_address,
                start.elapsed().as_millis()
            );
            self.database.borrow_mut().commit_batch(address_batch)?;
        }

        maybe_await!(self.client.borrow_mut().sync(
            None,
            self.database.borrow_mut().deref_mut(),
            noop_progress(),
        ))
    }

    #[maybe_async]
    pub fn broadcast(&self, tx: Transaction) -> Result<Txid, Error> {
        maybe_await!(self.client.borrow_mut().broadcast(&tx))?;

        Ok(tx.txid())
    }
}
