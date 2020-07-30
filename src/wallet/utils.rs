use std::collections::HashSet;

use bitcoin::util::bip32::ChildNumber;
use bitcoin::Address;

use miniscript::{MiniscriptKey, Satisfier};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AddressTypes {
    Pkh,
    ShWpkh,
    Wpkh,
    Sh,
    ShWsh,
    Wsh,
}

pub trait AddressViewer {
    fn supported_types(&self) -> HashSet<AddressTypes>;

    fn show_address(&self, child: ChildNumber, address: &Address) -> bool;
}

// De-facto standard "dust limit" (even though it should change based on the output type)
const DUST_LIMIT_SATOSHI: u64 = 546;

// we implement this trait to make sure we don't mess up the comparison with off-by-one like a <
// instead of a <= etc. The constant value for the dust limit is not public on purpose, to
// encourage the usage of this trait.
pub trait IsDust {
    fn is_dust(&self) -> bool;
}

impl IsDust for u64 {
    fn is_dust(&self) -> bool {
        *self <= DUST_LIMIT_SATOSHI
    }
}

pub struct After {
    pub current_height: Option<u32>,
    pub assume_height_reached: bool,
}

impl After {
    pub(crate) fn new(current_height: Option<u32>, assume_height_reached: bool) -> After {
        After {
            current_height,
            assume_height_reached,
        }
    }
}

impl<Pk: MiniscriptKey> Satisfier<Pk> for After {
    fn check_after(&self, n: u32) -> bool {
        if let Some(current_height) = self.current_height {
            current_height >= n
        } else {
            self.assume_height_reached
        }
    }
}

pub struct Older {
    pub current_height: Option<u32>,
    pub create_height: Option<u32>,
    pub assume_height_reached: bool,
}

impl Older {
    pub(crate) fn new(
        current_height: Option<u32>,
        create_height: Option<u32>,
        assume_height_reached: bool,
    ) -> Older {
        Older {
            current_height,
            create_height,
            assume_height_reached,
        }
    }
}

impl<Pk: MiniscriptKey> Satisfier<Pk> for Older {
    fn check_older(&self, n: u32) -> bool {
        if let Some(current_height) = self.current_height {
            // TODO: test >= / >
            current_height as u64 >= self.create_height.unwrap_or(0) as u64 + n as u64
        } else {
            self.assume_height_reached
        }
    }
}

pub struct ChunksIterator<I: Iterator> {
    iter: I,
    size: usize,
}

impl<I: Iterator> ChunksIterator<I> {
    pub fn new(iter: I, size: usize) -> Self {
        ChunksIterator { iter, size }
    }
}

impl<I: Iterator> Iterator for ChunksIterator<I> {
    type Item = Vec<<I as std::iter::Iterator>::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut v = Vec::new();
        for _ in 0..self.size {
            let e = self.iter.next();

            match e {
                None => break,
                Some(val) => v.push(val),
            }
        }

        if v.is_empty() {
            return None;
        }

        Some(v)
    }
}
