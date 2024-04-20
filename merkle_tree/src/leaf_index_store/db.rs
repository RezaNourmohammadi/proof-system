// use std::sync::Arc;

// use anyhow::Result;

// use crate::{AbsIndex, HashOfNull, Key, LeafIndex};

// use super::LeafIndexStore;

// struct DbLeafIndexStore<T> {
//     depth: usize,
//     hashes_of_null: HashOfNull<T>,
//     // db_client: ...
// }

// impl<T> DbLeafIndexStore<T> {
//     fn new(depth: usize) {
//         // TODO: Reza
//         todo!()
//     }
//     fn get_new_index(&self) -> LeafIndex {
//         // TODO: Reza
//         todo!()
//     }
// }

// impl<T> LeafIndexStore<T> for DbLeafIndexStore<T> {
//     fn get(&self, key: &Key) -> Result<(AbsIndex, Arc<T>)> {
//         // TODO: Reza
//         todo!()
//     }

//     fn put(&mut self, key: Key, value: (AbsIndex, Arc<T>)) {
//         // TODO: Reza
//         todo!()
//     }

//     fn get_new_index(&self) -> LeafIndex {
//         // TODO: Reza
//         todo!()
//     }
// }

// #[cfg(test)]
// mod tests {
//     // TODO: Reza
// }
