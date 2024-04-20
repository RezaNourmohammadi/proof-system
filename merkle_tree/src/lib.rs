mod hash_of_null;
mod hash_store;
mod leaf_index_store;
use crate::leaf_index_store::LeafIndexStore;
use anyhow::Result;
use common::utils::bits::bits2num;
use hash_of_null::HashOfNull;
use hash_store::local::LocalHashStore;
use hash_store::HashStore;
use k256::FieldElement;
use leaf_index_store::local::LocalLeafIndexStore;
use poseidon::Poseidon;
use std::fmt::Display;
use std::sync::Arc;

pub type Data = Vec<u8>;
pub type Hash = FieldElement;
pub type Key = Vec<u8>;
pub type KeyedHash = (Key, Hash);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sibling {
    pub hash: Hash,
    pub direction: HashDirection,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct AbsIndex(usize);

/// Leaf index
///
/// Example:
///
/// ```text
/// tree:
///                   0
///                 /   \
///                1     2
///               / \   / \
///              3   4 5   6
/// leaf_index: [0,  1,2,  3]
/// ```
struct LeafIndex {
    i: usize,
    depth: usize,
}
impl From<LeafIndex> for AbsIndex {
    fn from(value: LeafIndex) -> Self {
        let abs_index = value.i + 2usize.pow(value.depth as u32 - 1) - 1;
        AbsIndex(abs_index)
    }
}
/// Leaf index
///
/// Example:
///
/// ```text
/// tree:
/// level 0           0
///                 /   \
/// level 1        1     2
///               / \   / \
/// level 2      3   4 5   6
/// leaf_index: [0,  1,2,  3]
/// ```
struct Level(usize);
impl From<AbsIndex> for Level {
    fn from(value: AbsIndex) -> Self {
        let level = f64::log2((value.0 + 1) as f64).floor() as usize;
        Level(level)
    }
}

/// The binary tree of hashes is used to efficiently calculate the
/// Merkle root of a set of data points. Each node in the tree represents
/// the hash value of a subset of the data points, and the root node
/// represents the hash value of the entire set. The tree is constructed
/// by hashing together the hash values of the left and right
/// subtree at each level.
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleTree {
    /// The leaf index is a mapping of each leaf node in the Merkle tree to its
    /// corresponding index in the hash array. This allows for efficient lookup of
    /// of specific data points in the hash array during proof construction.
    ///
    /// Example:
    /// Leaf nodes in the Merkle tree:
    /// ```text
    ///               root
    ///           /         \
    ///         H(a,b)    H(c,d)
    ///        /     \    /     \
    ///       a      b   c      d
    /// ```
    ///
    /// Corresponding indices in the hash array: [3, 4, 5, 6]
    /// (where H(a,b) = hash(data[a] + data[b]) and so on)
    ///
    /// The tree is first assumed to be initialized with nulls like this
    /// ```text
    /// l0       0000
    ///          /   \
    /// l1      00    00
    ///        / \   / \
    /// l2    0   0  0  0
    /// ```
    /// Arc has been chosen to avoid cloning the hash when inserting into the HashMap.
    leaf_index: LocalLeafIndexStore<Hash>,

    /// the binary tree of hashes in a standard array representation.
    /// The root is at index 0. Total number of nodes in a perfect tree is calculated as
    /// 2^(round_down(log_2(n_leaves)) + 1) - 1.
    /// 2*i + 1 and 2*i + 2 are the left and right children of a node i
    hashes: LocalHashStore<Hash>,
    pub depth: usize,
}

impl Display for MerkleTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MerkleTree {{ hashes: {:?} }}", self.hashes)
    }
}

/// Which side to put Hash on when concatenating proof hashes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default, Clone)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatenating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

impl Display for Proof<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Proof {{ hashes: {:?} }}",
            self.hashes // .iter()
                        // .map(|(dir, h)| (dir, hex::encode(h)))
                        // .collect::<Vec<_>>()
        )
    }
}

#[inline(always)]
pub fn index(abs_index: usize, depth: usize) -> usize {
    abs_index - 2usize.pow(depth as u32 - 1) + 1
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        Self {
            leaf_index: LocalLeafIndexStore::new(depth),
            hashes: LocalHashStore::new(depth),
            depth,
        }
    }
    /// Gets root hash for this tree
    pub fn root(&self) -> Hash {
        self.hashes.get(&AbsIndex(0))
    }

    pub fn insert_leaf(&mut self, key: &Key, data: &Data) -> Result<(Hash, Hash, Vec<Sibling>)> {
        // check if leaf is there already
        let abs_index = self.leaf_index.get(key)?.0;
        let hash = hash_data(data);
        self.leaf_index
            .put(key.clone(), (abs_index, Arc::new(hash.clone())));
        Ok(self.insert_to_hashes(abs_index, &hash))
    }
    pub fn get_leaf(&self, key: &Key) -> Result<Hash> {
        self.leaf_index.get(key).map(|x| x.1.as_ref().clone())
    }

    /// first get all siblings indices, retrieve their hashes,
    /// calculate new hashes
    /// then get all indices to update
    /// then update them
    /// return root hash
    fn insert_to_hashes(&mut self, abs_index: AbsIndex, hash: &Hash) -> (Hash, Hash, Vec<Sibling>) {
        let indices_to_root = Self::get_path_to_root_indices(abs_index);
        let siblings = self.get_siblings(abs_index);
        let new_hashes = Self::get_new_hashes(hash, &siblings);
        self.hashes.put_many(&indices_to_root, &new_hashes);
        (
            new_hashes[0],
            new_hashes[new_hashes.len() - 1].clone(),
            siblings,
        )
    }
    fn get_new_hashes(hash: &Hash, siblings: &Vec<Sibling>) -> Vec<Hash> {
        let mut new_hashes = vec![hash.clone()];
        let mut new_parent_hash = hash.clone();
        for sibling in siblings {
            new_parent_hash = match sibling.direction {
                HashDirection::Left => hash_concat(&sibling.hash, &new_parent_hash),
                HashDirection::Right => hash_concat(&new_parent_hash, &sibling.hash),
            };
            new_hashes.push(new_parent_hash);
        }
        new_hashes
    }
    fn get_path_to_root_indices(abs_index: AbsIndex) -> Vec<AbsIndex> {
        let mut indices = vec![abs_index];
        while let Some(parent_index) = Self::get_parent_index(indices.last().unwrap().clone()) {
            indices.push(parent_index);
        }
        indices
    }

    #[inline(always)]
    fn get_parent_index(abs_index: AbsIndex) -> Option<AbsIndex> {
        if abs_index.0 == 0 {
            None
        } else {
            Some(AbsIndex((abs_index.0 - 1) / 2))
        }
    }

    #[inline(always)]
    /// Gets the sibling for the given index
    /// Example:
    /// ```text
    /// tree:
    ///                   0
    ///                 /   \
    ///                1     2
    ///               / \   / \
    ///              3   4 5   6
    /// input: 3
    /// output: (4, Right)
    ///
    /// input: 4
    /// output: (3, Left)
    /// ```
    fn get_sibling_index(abs_index: AbsIndex) -> Option<AbsIndex> {
        if abs_index.0 == 0 {
            return None;
        };
        let abs_index_int = abs_index.0;
        if abs_index_int % 2 == 0 {
            Some(AbsIndex(abs_index_int - 1))
        } else {
            Some(AbsIndex(abs_index_int + 1))
        }
    }

    /// Gets a list of siblings for the given index
    ///
    /// Example:
    ///
    /// tree:
    /// ```text
    ///                    0
    ///                  /   \
    ///                 1     2
    ///                / \   / \
    ///               3   4 5   6
    /// leaf_index:   0   1 2   3
    /// input: 3
    /// abs_index: 6
    /// output: [(5, Left), (1, Left)]
    /// ```
    #[inline(always)]
    fn get_siblings(&self, abs_index: AbsIndex) -> Vec<Sibling> {
        let sibling_indices = Self::get_sibling_indices(abs_index);
        let sibling_hashes = self.hashes.get_many(&sibling_indices);
        sibling_indices
            .iter()
            .zip(sibling_hashes)
            .map(|(i, h)| Sibling {
                hash: h,
                direction: if i.0 % 2 == 0 {
                    HashDirection::Right
                } else {
                    HashDirection::Left
                },
            })
            .collect()
    }
    fn get_sibling_indices(abs_index: AbsIndex) -> Vec<AbsIndex> {
        let mut sibling_indices = vec![];
        let mut abs_index = abs_index;
        while let Some(sibling) = Self::get_sibling_index(abs_index) {
            sibling_indices.push(sibling);
            abs_index = Self::get_parent_index(abs_index).unwrap();
        }
        sibling_indices
    }
}

pub fn hash_data(data: &Data) -> Hash {
    let num = bits2num(data);
    let input = [num, FieldElement::from(0)];
    let mut poseidon = Poseidon::default();
    let poseidon_hash = poseidon.hash(&input).normalize();
    return poseidon_hash;
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    // let h3 = h1.iter().chain(h2).copied().collect();
    // hash_data(&h3)
    let mut poseidon = Poseidon::default();
    let input = [h1.clone(), h2.clone()];
    poseidon.hash(&input).normalize()
}

#[cfg(test)]
mod tests {

    use poseidon::PrimeField;

    use super::*;
    const MESSAGE: &str =
        "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
    const ETH_ADRESS: &str = "0x631438556b66c4908579Eab920dc162FF58958ea";

    /// test utility functions
    #[test]
    fn test_get_index() {
        let index = LeafIndex { i: 0, depth: 3 };
        assert_eq!(AbsIndex(3), index.into());
    }

    #[test]
    fn test_insert_leaf_at() {
        let mut tree = MerkleTree::new(3);

        let input_string = MESSAGE;
        let data = input_string.bytes().collect::<Vec<u8>>();

        let key = ETH_ADRESS;
        let _ = tree.insert_leaf(&key.as_bytes().to_vec(), &data);

        let expected_new_first_hash = FieldElement::from_str_vartime(
            "101176329091698335529460225682959434402786110142788260993893987876843326118705",
        )
        .unwrap()
        .normalize();

        let new_first_leaf = tree.hashes.get(&AbsIndex(3)).normalize();
        assert_eq!(new_first_leaf, expected_new_first_hash);

        let new_first_intermediate_hash = tree.hashes.get(&AbsIndex(1)).normalize();
        let expected_new_first_intermediate_hash = FieldElement::from_str_vartime(
            "22601119498902732566050259690838599920396049850589890003238364182086538814383",
        )
        .unwrap()
        .normalize();

        assert_eq!(
            expected_new_first_intermediate_hash,
            new_first_intermediate_hash
        );

        let new_second_intermediate_hash = tree.hashes.get(&AbsIndex(2)).normalize();
        let expected_new_second_intermediate_hash = FieldElement::from_str_vartime(
            "18960378590443015153965892039080763573460244091359764013472153018086901292684",
        )
        .unwrap()
        .normalize();

        assert_eq!(
            expected_new_second_intermediate_hash,
            new_second_intermediate_hash
        );

        let new_expected_root = FieldElement::from_str_vartime(
            "31891008891186972713391051354062095786110945537894632936012479135082060943704",
        )
        .unwrap()
        .normalize();
        let new_root = tree.root().normalize();
        assert_eq!(new_expected_root, new_root);
    }

    #[test]
    fn test_get_path_to_root_indices() {
        let abs_index = AbsIndex(6);
        let indices = MerkleTree::get_path_to_root_indices(abs_index);
        assert_eq!(indices, vec![AbsIndex(6), AbsIndex(2), AbsIndex(0)]);
    }

    #[test]
    fn test_get_siblings() {
        // TODO NikZak: test
    }

    /// test edge cases
    #[test]
    fn test_empty() {
        let tree = MerkleTree::new(3);

        let expected_leaf_hashes = FieldElement::from_str_vartime(
            "19186055882243973308626442936814331228632512745896196441702367494386046454885",
        )
        .unwrap()
        .normalize();

        let fisrt_leaf = tree.hashes.get(&AbsIndex(3)).normalize();
        let second_leaf = tree.hashes.get(&AbsIndex(4)).normalize();
        let third_leaf = tree.hashes.get(&AbsIndex(5)).normalize();
        let fourth_leaf = tree.hashes.get(&AbsIndex(6)).normalize();

        assert_eq!(fisrt_leaf, expected_leaf_hashes);
        assert_eq!(second_leaf, expected_leaf_hashes);
        assert_eq!(third_leaf, expected_leaf_hashes);
        assert_eq!(fourth_leaf, expected_leaf_hashes);

        let first_intermediate_hash = tree.hashes.get(&AbsIndex(2)).normalize();
        let second_intermediate_hash = tree.hashes.get(&AbsIndex(1)).normalize();

        let expected_intermediate_hash = FieldElement::from_str_vartime(
            "18960378590443015153965892039080763573460244091359764013472153018086901292684",
        )
        .unwrap()
        .normalize();

        assert_eq!(first_intermediate_hash, expected_intermediate_hash);
        assert_eq!(second_intermediate_hash, expected_intermediate_hash);

        let root = tree.root().normalize();
        let expected_root = FieldElement::from_str_vartime(
            "57229376209049585136773117581839759840059304365154418192974084211719181400451",
        )
        .unwrap()
        .normalize();

        assert_eq!(root, expected_root, "{}", tree);
    }
}
