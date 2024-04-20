use std::collections::HashMap;

use crate::{
    hash_of_null::{HashOfNull, NullHash},
    AbsIndex, Level,
};

use super::HashStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHashStore<T> {
    hashes: HashMap<usize, T>,
    depth: usize,
    hashes_of_null: HashOfNull<T>,
}
impl<T: NullHash<T>> LocalHashStore<T> {
    pub fn new(depth: usize) -> Self {
        Self {
            hashes: HashMap::new(),
            depth,
            hashes_of_null: T::null_hash(depth - 1),
        }
    }
}

impl<T: Clone> HashStore<T> for LocalHashStore<T> {
    fn return_hash_of_null(&self, abs_index: AbsIndex) -> T {
        let level = Level::from(abs_index);
        self.hashes_of_null.get(level)
    }
    fn get_many(&self, keys: &[AbsIndex]) -> Vec<T> {
        // TODO: Reza impl database
        keys.iter()
            .map(|k| {
                self.hashes
                    .get(&k.0)
                    .map_or_else(|| self.return_hash_of_null(k.clone()), |x| (*x).clone())
            })
            .collect()
    }
    fn get(&self, key: &AbsIndex) -> T {
        // TODO: Reza impl database
        match self.hashes.get(&key.0) {
            Some(hash) => hash.clone(),
            None => self.return_hash_of_null(key.clone()),
        }
    }
    fn put_many(&mut self, keys: &[AbsIndex], values: &[T]) {
        // TODO: Reza impl database
        for (k, v) in keys.iter().zip(values.iter()) {
            self.hashes.insert(k.0, v.clone());
        }
    }
}

#[cfg(test)]
mod tests {}
