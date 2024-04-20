use std::{collections::HashMap, sync::Arc};

use anyhow::Result;

use crate::hash_of_null::NullHash;
use crate::{AbsIndex, HashOfNull, Key, LeafIndex};

use super::LeafIndexStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLeafIndexStore<T> {
    leaf_index: HashMap<Key, (usize, Arc<T>)>,
    depth: usize,
    hashes_of_null: HashOfNull<T>,
}
impl<T: NullHash<T>> LocalLeafIndexStore<T> {
    pub fn new(depth: usize) -> Self {
        Self {
            leaf_index: HashMap::new(),
            depth,
            hashes_of_null: T::null_hash(depth - 1),
        }
    }
}

impl<T: Clone> LeafIndexStore<T> for LocalLeafIndexStore<T> {
    fn get(&self, key: &Key) -> Result<(AbsIndex, Arc<T>)> {
        let res = match self.leaf_index.get(key) {
            None => {
                let new_index = self.get_new_index();
                if new_index.i >= 2usize.pow(self.depth as u32 - 1) {
                    return Err(anyhow::anyhow!("index out of range"));
                }
                (new_index.into(), Arc::new(self.hashes_of_null.last()))
            }
            Some(x) => (AbsIndex(x.0), x.1.clone()),
        };

        Ok(res)
    }
    fn put(&mut self, key: Key, value: (AbsIndex, Arc<T>)) {
        self.leaf_index.insert(key, (value.0 .0, value.1));
    }
    fn get_new_index(&self) -> LeafIndex {
        LeafIndex {
            i: self.leaf_index.len(),
            depth: self.depth,
        }
    }
}

#[cfg(test)]
mod tests {

    use k256::FieldElement;

    use super::*;
    use crate::Hash;

    #[test]
    fn test_get() {
        let depth = 3;
        let mut store = LocalLeafIndexStore::<FieldElement>::new(depth);

        // Test case 1: Key not found
        let key1 = vec![0 as u8; 4];
        let result1 = store.get(&key1);
        assert!(result1.is_ok());
        let (index1, hash1) = result1.unwrap();
        assert_eq!(index1, AbsIndex(3));
        assert_eq!(*hash1, Hash::null_hash(depth - 1).last());

        // Test case 2: Key found
        let key2 = vec![1 as u8; 4];
        let hash2 = Arc::new(Hash::from(0));
        store.put(key2.clone(), (AbsIndex(4), hash2.clone()));
        let result2 = store.get(&key2);
        assert!(result2.is_ok());
        let (index2, hash3) = result2.unwrap();
        assert_eq!(index2, AbsIndex(4));
        assert_eq!(hash2, hash3);

        // Test case 3: Key not but index out of range
        store.put(key1.clone(), (AbsIndex(3), hash2.clone()));
        let key3 = vec![2 as u8; 4];
        store.put(key3.clone(), (AbsIndex(5), hash2.clone()));
        let key4 = vec![3 as u8; 4];
        store.put(key4.clone(), (AbsIndex(6), hash2.clone()));
        let key5 = vec![4 as u8; 4];
        let result3 = store.get(&key5);

        assert!(result3.is_err());
    }

    #[test]
    fn test_put() {
        let depth = 3;
        let mut store = LocalLeafIndexStore::<Hash>::new(depth);

        let key = vec![0 as u8; 4];
        let index = AbsIndex(0);
        let hash = Arc::new(Hash::from(0));

        store.put(key.clone(), (index.clone(), hash.clone()));

        let result = store.get(&key);
        assert!(result.is_ok());
        let (stored_index, stored_hash) = result.unwrap();
        assert_eq!(stored_index, index);
        assert_eq!(stored_hash, hash);
    }

    #[test]
    fn test_get_new_index() {
        let depth = 3;
        let mut store = LocalLeafIndexStore::<Hash>::new(depth);

        // first with empty store
        let index1 = store.get_new_index();
        assert_eq!(index1.i, 0);
        assert_eq!(index1.depth, depth);
        let key = vec![0 as u8; 4];
        let hash = Arc::new(Hash::from(0));

        // then with one element in store
        store.put(key.clone(), (index1.into(), hash.clone()));
        let index1 = store.get_new_index();
        assert_eq!(index1.i, 1);
    }
}
