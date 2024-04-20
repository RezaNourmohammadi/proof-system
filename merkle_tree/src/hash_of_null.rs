use crate::{hash_concat, hash_data, Hash, Level};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashOfNull<T>(Vec<T>);
impl<T: Clone> HashOfNull<T> {
    pub fn get(&self, level: Level) -> T {
        self.0[level.0].clone()
    }
    pub fn last(&self) -> T {
        self.0[self.0.len() - 1].clone()
    }
}
pub trait NullHash<T> {
    fn null_hash(max_level: usize) -> HashOfNull<T>;
}

/// ```text
/// l0       0000
///          /   \
/// l1      00    00
///        / \   / \
/// l2    0   0  0  0
/// ```
impl NullHash<Hash> for Hash {
    fn null_hash(max_level: usize) -> HashOfNull<Hash> {
        let mut hashes_of_null = Vec::with_capacity(max_level);
        let mut level_hash = hash_data(&vec![0u8; 32]);
        for _ in 0..max_level + 1 {
            hashes_of_null.push(level_hash);
            level_hash = hash_concat(&level_hash, &level_hash);
        }
        HashOfNull(hashes_of_null.iter().rev().map(|x| x.clone()).collect())
    }
}
