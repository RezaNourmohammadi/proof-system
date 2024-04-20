use crate::AbsIndex;

pub mod db;
pub mod local;

pub trait HashStore<T> {
    fn get_many(&self, keys: &[AbsIndex]) -> Vec<T>;
    fn get(&self, key: &AbsIndex) -> T;
    fn put_many(&mut self, keys: &[AbsIndex], values: &[T]);
    fn return_hash_of_null(&self, abs_index: AbsIndex) -> T;
}
