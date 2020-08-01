use std::sync::Arc;
use std::ops::Deref;
use std::collections::HashSet;
use std::sync::mpsc::{channel, Receiver, Sender};

use bitcoin::{Transaction, Txid};

use crate::database::{BatchDatabase, DatabaseUtils};
use crate::error::Error;

pub mod utils;

#[cfg(feature = "electrum")]
pub mod electrum;
#[cfg(feature = "electrum")]
pub use self::electrum::ElectrumBlockchain;

#[cfg(feature = "esplora")]
pub mod esplora;
#[cfg(feature = "esplora")]
pub use self::esplora::EsploraBlockchain;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    FullHistory,
    GetAnyTx,
}

pub trait Blockchain {
    fn is_online(&self) -> bool;

    fn offline() -> Self;
}

impl<T: Blockchain> Blockchain for Arc<T> {
    fn is_online(&self) -> bool {
        self.deref().is_online()
    }

    fn offline() -> Self {
        Arc::new(T::offline())
    }
}

pub struct OfflineBlockchain;
impl Blockchain for OfflineBlockchain {
    fn offline() -> Self {
        OfflineBlockchain
    }

    fn is_online(&self) -> bool {
        false
    }
}

#[maybe_async]
pub trait OnlineBlockchain: Blockchain {
    fn get_capabilities(&self) -> HashSet<Capability>;

    fn setup<D: BatchDatabase + DatabaseUtils, P: Progress>(
        &mut self,
        stop_gap: Option<usize>,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error>;
    fn sync<D: BatchDatabase + DatabaseUtils, P: Progress>(
        &mut self,
        stop_gap: Option<usize>,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error> {
        maybe_await!(self.setup(stop_gap, database, progress_update))
    }

    fn get_tx(&mut self, txid: &Txid) -> Result<Option<Transaction>, Error>;
    fn broadcast(&mut self, tx: &Transaction) -> Result<(), Error>;

    fn get_height(&mut self) -> Result<usize, Error>;
}

/* #[maybe_async]
impl<T: OnlineBlockchain> OnlineBlockchain for Arc<T> {
    fn get_capabilities(&self) -> HashSet<Capability> {
        self.deref().get_capabilities()
    }

    fn setup<D: BatchDatabase + DatabaseUtils, P: Progress>(
        &mut self,
        stop_gap: Option<usize>,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error> {
    }

    fn sync<D: BatchDatabase + DatabaseUtils, P: Progress>(
        &mut self,
        stop_gap: Option<usize>,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error> {
        maybe_await!(self.setup(stop_gap, database, progress_update))
    }

    fn get_tx(&mut self, txid: &Txid) -> Result<Option<Transaction>, Error>;
    fn broadcast(&mut self, tx: &Transaction) -> Result<(), Error>;

    fn get_height(&mut self) -> Result<usize, Error>;
}*/

pub type ProgressData = (f32, Option<String>);

pub trait Progress {
    fn update(&self, progress: f32, message: Option<String>) -> Result<(), Error>;
}

pub fn progress() -> (Sender<ProgressData>, Receiver<ProgressData>) {
    channel()
}

impl Progress for Sender<ProgressData> {
    fn update(&self, progress: f32, message: Option<String>) -> Result<(), Error> {
        if progress < 0.0 || progress > 100.0 {
            return Err(Error::InvalidProgressValue(progress));
        }

        self.send((progress, message))
            .map_err(|_| Error::ProgressUpdateError)
    }
}

pub struct NoopProgress;

pub fn noop_progress() -> NoopProgress {
    NoopProgress
}

impl Progress for NoopProgress {
    fn update(&self, _progress: f32, _message: Option<String>) -> Result<(), Error> {
        Ok(())
    }
}
