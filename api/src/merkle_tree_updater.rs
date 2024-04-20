use crate::{eff_ecdsa_input::fe_to_biguint, server::SignedUserProfileUpdate};
use common::utils::bits::pad_msg;
use merkle_tree::{Hash, MerkleTree, Sibling};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::debug;

use common::BIT_SIZE;

pub struct MerkleTreeUpdater {
    merkle_tree: MerkleTree,
    rx: Receiver<SignedUserProfileUpdate>,
    tx: Sender<(Hash, SignedUserProfileUpdate, Hash, Vec<Sibling>)>,
}
impl MerkleTreeUpdater {
    pub fn new(
        merkle_tree: MerkleTree,
        rx: Receiver<SignedUserProfileUpdate>,
        tx: Sender<(Hash, SignedUserProfileUpdate, Hash, Vec<Sibling>)>,
    ) -> Self {
        Self {
            merkle_tree,
            rx,
            tx,
        }
    }
    pub async fn run(&mut self) {
        debug!("Merkle Tree Updater started");
        debug!("Merkle Tree depth: {}", self.merkle_tree.depth);
        debug!(
            "Merkle Tree root: {:?}",
            fe_to_biguint(&self.merkle_tree.root())
        );
        while let Some(update) = self.rx.recv().await {
            let padded_msg = pad_msg(update.profile_update.unparsed_profile.as_bytes(), BIT_SIZE);
            let eth_address = update.profile_update.parsed_profile.wallet_address.clone();
            let old_leaf = self
                .merkle_tree
                .get_leaf(&eth_address.as_bytes().to_vec())
                .unwrap();
            let (_, new_root, siblings) = self
                .merkle_tree
                .insert_leaf(&eth_address.as_bytes().to_vec(), &padded_msg)
                .unwrap();
            debug!("New root: {:?}", fe_to_biguint(&new_root));
            let _ = self.tx.send((new_root, update, old_leaf, siblings)).await;
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::server::UserProfileUpdate;

    use super::*;
    #[tokio::test]
    async fn test_merkle_tree_updater() {
        // Create a test UserProfileUpdate
        let profile_update: UserProfileUpdate =
            "10234345, 0x53e16f6d33c1809c14ba489a6917e9de849ab20c, tom, hanks"
                .try_into()
                .unwrap();
        let signature = "not real".to_string();
        let signed_profile_update =
            SignedUserProfileUpdate::from_profile_update(profile_update, signature);

        // Create a MerkleTreeUpdater instance
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let (tx_result, mut rx_result) = tokio::sync::mpsc::channel(10);
        let mut updater = MerkleTreeUpdater {
            merkle_tree: MerkleTree::new(3),
            rx,
            tx: tx_result,
        };
        let old_root = updater.merkle_tree.root();

        // Spawn the updater task
        tokio::task::spawn(async move {
            updater.run().await;
        });

        // Send the test update to the updater
        tx.send(signed_profile_update).await.unwrap();

        // Receive the new root from the updater
        let (new_root, _, _, _) = rx_result.recv().await.unwrap();

        // Assert that the new root is not empty
        assert_ne!(old_root, new_root);
    }
}
