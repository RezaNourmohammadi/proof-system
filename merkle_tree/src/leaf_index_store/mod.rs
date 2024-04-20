use std::sync::Arc;

use anyhow::Result;

use crate::{AbsIndex, Key, LeafIndex};

pub mod db;
pub mod local;

pub trait LeafIndexStore<T> {
    fn get(&self, key: &Key) -> Result<(AbsIndex, Arc<T>)>;
    fn put(&mut self, key: Key, value: (AbsIndex, Arc<T>));
    fn get_new_index(&self) -> LeafIndex;
}
