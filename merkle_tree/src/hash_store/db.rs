// use crate::{hash_of_null::HashOfNull, AbsIndex};

// use super::HashStore;

// pub struct DbHashStore<T> {
//     depth: usize,
//     hashes_of_null: HashOfNull<T>,
//     // db
// }

// impl<T> DbHashStore<T> {
//     pub fn new(depth: usize) -> Self {
//         // TODO: Reza
//         todo!()
//     }
// }

// impl<T> HashStore<T> for DbHashStore<T> {
//     fn return_hash_of_null(&self, abs_index: AbsIndex) -> T {
//         // TODO Reza
//         todo!()
//     }
//     fn get_many(&self, keys: &[AbsIndex]) -> Vec<T> {
//         // TODO Reza
//         todo!()
//     }
//     fn get(&self, key: &AbsIndex) -> T {
//         // TODO Reza
//         todo!()
//     }
//     fn put_many(&mut self, keys: &[AbsIndex], values: &[T]) {
//         // TODO Reza
//         todo!()
//     }
// }

// #[cfg(test)]
// mod tests {
//     // TODO: Reza
// }
