use std::{collections::HashMap, env::current_dir, sync::Arc};

use nova_scotia::{circom::circuit::R1CS, FileLocation, F};

use nova_snark::{traits::Group, PublicParams, RecursiveSNARK};

use serde::{Deserialize, Serialize};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};
use tracing::debug;

use crate::{proof_system_message::ProofSystemMessage, C1, C2, G1, G2};
use nova_scotia::circom::reader::generate_witness_from_wasm;

use std::path::Path;

use nova_scotia::circom::circuit::CircomCircuit;
use nova_snark::traits::circuit::TrivialCircuit;
use num_bigint::BigInt;
use num_traits::Num;
use serde_json::Value;

pub const NUM_FOLDS: usize = 2;

pub struct IVCProofFolder {
    rx: Receiver<ProofSystemMessage>,
    tx: Sender<RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>>,
    pp: Arc<PublicParams<G1, G2, C1<G1>, C2<G2>>>,
    r1cs: R1CS<<G1 as Group>::Scalar>,
    start_public_input: Vec<<G1 as Group>::Scalar>,
    counter: usize,
}
impl IVCProofFolder {
    pub fn new(
        rx: Receiver<ProofSystemMessage>,
        tx: Sender<RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>>,
        pp: Arc<PublicParams<G1, G2, C1<G1>, C2<G2>>>,
        r1cs: R1CS<<G1 as Group>::Scalar>,
        start_public_input: Vec<<G1 as Group>::Scalar>,
    ) -> Self {
        Self {
            rx,
            tx,
            pp,
            r1cs,
            start_public_input,
            counter: 0,
        }
    }
    pub async fn run(&mut self) {
        debug!("Proof Folder started");
        let witness_generator_file =
            FileLocation::PathBuf("../circuits/src/merkle_tree/ivc_js/ivc.wasm".into());
        let root = current_dir().unwrap();
        let witness_generator_output = root.join("circom_witness.wtns");
        let start_public_input_hex = self
            .start_public_input
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect::<Vec<String>>();
        let update = self.rx.recv().await.unwrap();
        debug!("received first update");
        let start = Instant::now();
        let witness = compute_witness::<G1, G2>(
            start_public_input_hex.clone(),
            update,
            witness_generator_file.clone(),
            &witness_generator_output,
        );
        let duration = start.elapsed();
        debug!("witness creation time {:?}", duration);
        let circuit = CircomCircuit {
            r1cs: self.r1cs.clone(),
            witness: Some(witness),
        };
        let circuit_secondary = TrivialCircuit::default();
        // let z0_secondary = vec![<G2 as Group>::Scalar::ZERO];
        let z0_secondary = vec![<G2 as Group>::Scalar::zero()];
        let start = Instant::now();
        let mut recursive_snark = RecursiveSNARK::<G1, G2, C1<G1>, C2<G2>>::new(
            self.pp.as_ref(),
            &circuit,
            &circuit_secondary,
            self.start_public_input.clone(),
            z0_secondary.clone(),
        );
        let duration = start.elapsed();
        debug!("Recursive SNARK creation time {:?}", duration);
        let start = Instant::now();
        let _ = recursive_snark.prove_step(
            self.pp.as_ref(),
            &circuit,
            &circuit_secondary,
            self.start_public_input.clone(),
            z0_secondary.clone(),
        );
        let duration = start.elapsed();
        debug!("folding time {:?}", duration);
        debug!(
            "recursive snark proof size {:.2} Mb",
            serde_json::to_string(&recursive_snark).unwrap().len() as f64 / 1_000_000.0
        );
        let current_public_output = circuit.get_public_outputs();
        let mut current_public_input: Vec<String> = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();
        self.counter += 1;
        if self.counter % NUM_FOLDS == 0 {
            let _ = self.tx.send(recursive_snark.clone()).await;
        }

        while let Some(update) = self.rx.recv().await {
            debug!("received update");
            let start = Instant::now();

            let witness = compute_witness::<G1, G2>(
                current_public_input.clone(),
                update,
                witness_generator_file.clone(),
                &witness_generator_output,
            );
            let duration = start.elapsed();
            debug!("witness creation time {:?}", duration);
            let circuit = CircomCircuit {
                r1cs: self.r1cs.clone(),
                witness: Some(witness),
            };

            // fold the new proofsystem message

            let start = Instant::now();
            let _ = recursive_snark.prove_step(
                self.pp.as_ref(),
                &circuit,
                &circuit_secondary,
                self.start_public_input.clone(),
                z0_secondary.clone(),
            );
            let duration = start.elapsed();
            debug!("nova prove time {:?}", duration);
            debug!(
                "recursive snark proof size {:.2} Mb",
                serde_json::to_string(&recursive_snark).unwrap().len() as f64 / 1_000_000.0
            );
            self.counter += 1;
            if self.counter % NUM_FOLDS == 0 {
                let _ = self.tx.send(recursive_snark.clone()).await;
            }
            let current_public_output = circuit.get_public_outputs();
            current_public_input = current_public_output
                .iter()
                .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
                .collect();
            let start = Instant::now();
            let res = recursive_snark.verify(
                self.pp.as_ref(),
                self.counter,
                &self.start_public_input,
                &z0_secondary,
            );
            debug!(
                "RecursiveSNARK::verify: {:?}, took {:?}",
                res.is_ok(),
                start.elapsed()
            );
            assert!(res.is_ok());
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CircomInput {
    step_in: Vec<String>,

    #[serde(flatten)]
    extra: HashMap<String, Value>,
}
fn compute_witness<G1, G2>(
    current_public_input: Vec<String>,
    private_input: HashMap<String, Value>,
    witness_generator_file: FileLocation,
    witness_generator_output: &Path,
) -> Vec<<G1 as Group>::Scalar>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let decimal_stringified_input: Vec<String> = current_public_input
        .iter()
        .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
        .collect();

    let input = CircomInput {
        step_in: decimal_stringified_input.clone(),
        extra: private_input.clone(),
    };

    let is_wasm = true;
    let input_json = serde_json::to_string(&input).unwrap();

    if is_wasm {
        generate_witness_from_wasm::<F<G1>>(
            &witness_generator_file,
            &input_json,
            &witness_generator_output,
        )
    } else {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::get_pp;
    use crate::proof_system_message::make_proof_system_msg;
    use crate::proof_system_message::tests::{
        dummy_first_hash, dummy_siblings, dummy_signature, dummy_user_profile_update, zero_hash,
    };
    use crate::server::SignedUserProfileUpdate;
    use ff::PrimeField;
    use nova_scotia::circom::reader::load_r1cs;
    use tracing::debug;
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_run() {
        debug!("Starting test");
        let (tx, rx_folder) = tokio::sync::mpsc::channel(100);
        let (tx_folder, mut rx) = tokio::sync::mpsc::channel(100);

        let update = dummy_user_profile_update();
        let signature = dummy_signature();
        let signed_update = SignedUserProfileUpdate::from_profile_update(update, signature);
        let prev_leaf_hash = zero_hash();
        let siblings = dummy_siblings();
        let prev_leaf_hash_new = dummy_first_hash();

        let mut proof_system_msg =
            make_proof_system_msg(&signed_update, &prev_leaf_hash, &siblings);
        let proof_system_msg1 =
            make_proof_system_msg(&signed_update, &prev_leaf_hash_new, &siblings);
        debug!("Created proof system message {:?}", proof_system_msg);

        let circuit_file = "../circuits/src/merkle_tree/ivc.r1cs";
        let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file.into()));
        debug!("Loaded r1cs");
        let public_params_file = "../circuits/src/merkle_tree/ivc.params";
        let pp = get_pp(public_params_file, &r1cs);
        debug!("Created pp");
        // Folder process instance
        let start_public_input = vec![
            F::<G1>::from_str_vartime(
                "57229376209049585136773117581839759840059304365154418192974084211719181400451",
            )
            .unwrap(),
            F::<G1>::from_str_vartime("170345900").unwrap(),
        ];
        let mut folder = IVCProofFolder::new(
            rx_folder,
            tx_folder,
            Arc::clone(&pp),
            r1cs,
            start_public_input,
        );
        debug!("Created Folder");

        // Spawn the Folder Task
        let _ = tokio::spawn(async move {
            folder.run().await;
        });
        let num_tries = 2;
        for i in 0..num_tries {
            tx.send(proof_system_msg.clone()).await.unwrap();
            debug!("Sent Update to Folder");
            if i == 0 {
                proof_system_msg = proof_system_msg1.clone();
            }
            if (i + 1) % NUM_FOLDS == 0 {
                rx.recv().await.unwrap();
            }
        }
    }
}
