mod compressed_proof_builder;
mod delayed_priority_queue;
mod eff_ecdsa_input;
mod ivc_proof_folder;
mod key_value_storage;
mod merkle_tree_updater;
mod proof_system_message;
mod server;
mod user;
use tracing::debug;

use delayed_priority_queue::{PriorityDelayQueue, PriorityDelayQueueRunner};
use ff::PrimeField;
use key_value_storage::LocalStorage;
use nova_scotia::circom::circuit::{CircomCircuit, R1CS};
use nova_snark::traits::circuit::TrivialCircuit;
use nova_snark::PublicParams;
use nova_snark::{provider::secp_secq::secp256k1, provider::secp_secq::secq256k1, traits::Group};
use std::sync::Arc;

use nova_scotia::F;
use nova_scotia::{circom::reader::load_r1cs, create_public_params, FileLocation};

use compressed_proof_builder::CompressedProofBuilder;
use ivc_proof_folder::IVCProofFolder;
use merkle_tree_updater::MerkleTreeUpdater;
use proof_system_message::ProofSystemMessageBuilder;

use server::run_server;
use tokio::{sync::mpsc::channel, time::Instant};

use merkle_tree::MerkleTree;

const PORT: u16 = 3000;
const MERKLE_TREE_DEPTH: usize = 3;
pub type G1 = secq256k1::Point;
pub type G2 = secp256k1::Point;

pub type C1<G> = CircomCircuit<<G as Group>::Scalar>;
pub type C2<G> = TrivialCircuit<<G as Group>::Scalar>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    debug!("Starting application");
    let tree = MerkleTree::new(MERKLE_TREE_DEPTH);
    let circuit_file = "../circuits/src/merkle_tree/ivc.r1cs";
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file.into()));
    let public_params_file = "../circuits/src/merkle_tree/ivc.params";
    // if file exists read params from file, else compute params and save to file as json
    let pp = get_pp(public_params_file, &r1cs);
    let start_public_input = vec![
        F::<G1>::from_str_vartime(
            "57229376209049585136773117581839759840059304365154418192974084211719181400451",
        )
        .unwrap(),
        F::<G1>::from_str_vartime("170345900").unwrap(),
    ];
    // create channels
    // merkle tree
    let (tx, rx_delayed_priority_queue) = channel(100);
    let (tx_delayed_priority_queue, rx_merkle_tree) = channel(100);
    // msg builder
    let (tx_merkle_tree, rx_msg_builder) = channel(100);
    // proof folder
    let (tx_msg_builder, rx_proof_folder) = channel(100);
    // compressed proof builder
    let (tx_proof_folder, rx_compressed_proof_builder) = channel(100);

    let delay_ms = 200;
    let storage = LocalStorage::new();
    let queue = Arc::new(PriorityDelayQueue::new(
        delay_ms,
        storage,
        tx_delayed_priority_queue,
    ));
    let mut delayed_priority_queue =
        PriorityDelayQueueRunner::new(rx_delayed_priority_queue, queue);
    let mut merkle_tree_updater = MerkleTreeUpdater::new(tree, rx_merkle_tree, tx_merkle_tree);
    let mut prove_system_msg_builder =
        ProofSystemMessageBuilder::new(rx_msg_builder, tx_msg_builder);
    let mut proof_folder = IVCProofFolder::new(
        rx_proof_folder,
        tx_proof_folder,
        Arc::clone(&pp),
        r1cs,
        start_public_input.clone(),
    );
    let mut compressed_proof_builder =
        CompressedProofBuilder::new(rx_compressed_proof_builder, pp, start_public_input);

    tokio::spawn(async move {
        delayed_priority_queue.run().await;
    });
    tokio::spawn(async move {
        merkle_tree_updater.run().await;
    });
    tokio::spawn(async move {
        prove_system_msg_builder.run().await;
    });
    tokio::spawn(async move {
        proof_folder.run().await;
    });
    tokio::spawn(async move {
        compressed_proof_builder.run().await;
    });

    run_server(PORT, tx).await;
}

pub fn get_pp(
    public_params_file: &str,
    r1cs: &R1CS<<G1 as Group>::Scalar>,
) -> Arc<PublicParams<G1, G2, C1<G1>, C2<G2>>> {
    let pp = if std::path::Path::new(public_params_file).exists() {
        debug!("Reading public parameters from file");
        let pp =
            serde_json::from_str(&std::fs::read_to_string(public_params_file).unwrap()).unwrap();
        Arc::new(pp)
    } else {
        debug!("Computing public parameters");
        let start = Instant::now();
        let pp = create_public_params::<G1, G2>(r1cs.clone());
        let duration = start.elapsed();
        debug!("Public parameters computed in {:?}", duration);
        std::fs::write(public_params_file, serde_json::to_string(&pp).unwrap()).unwrap();
        Arc::new(pp)
    };
    pp
}

#[cfg(test)]
mod tests {}
