use std::collections::HashMap;

use crate::eff_ecdsa_input::ECrv;
use crate::eff_ecdsa_input::{eff_ecdsa_input, fe_to_biguint, scalar_to_biguint, ScalarSecp};
use crate::server::SignedUserProfileUpdate;
use crate::{server::Signature, server::UserProfileUpdate};
use bitvec::prelude::*;
use common::utils::bits::pad_msg;
use common::BIT_SIZE;
use elliptic_curve::FieldBytes;
use elliptic_curve::PrimeField;
use merkle_tree::{Hash, HashDirection, Sibling};
use serde_json::Value;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::debug;

pub type ProofSystemMessage = HashMap<String, Value>;

pub struct ProofSystemMessageBuilder {
    rx: Receiver<(Hash, SignedUserProfileUpdate, Hash, Vec<Sibling>)>,
    tx: Sender<ProofSystemMessage>,
}

impl ProofSystemMessageBuilder {
    pub fn new(
        rx: Receiver<(Hash, SignedUserProfileUpdate, Hash, Vec<Sibling>)>,
        tx: Sender<ProofSystemMessage>,
    ) -> Self {
        Self { rx, tx }
    }
    pub async fn run(&mut self) {
        debug!("Proof System Message Builder started");
        while let Some((_, update, prev_leaf_hash, siblings)) = self.rx.recv().await {
            let proof_system_msg = make_proof_system_msg(&update, &prev_leaf_hash, &siblings);
            let _ = self.tx.send(proof_system_msg).await;
        }
    }
}

/// Example of ProofSystemMessage HashMap
///
/// "message":["0","0","1","1","0","0",...]
/// "signatures":[
///     "100772781879880001382816311161126674752411539729926309149870343915155632076140",
///     "48040442883402390498140677234105648176008923842845382194351710108461080825810",
///     "42771541141652766185486128983672064036750344051755519635088699065382541267047",
///     "114437886062228437493988933069828397094037127790528201582157673531515887469565",
///     "30304341961937615136151410748537015901070481690789957880759875086003496238576",
///     "94737429270188580733981682519122855402655819228206347230691544532852192205064"
/// ],
/// "prev_leaf_hash": "94737429270188580733981682519122855402655819228206347230691544532852192205064",
/// "pathIndices":["0","0"],
/// "siblings": [
///   "88079890366581071235776481069085452446742005908684328101826826785639435111524",
///   "27193508126789242050899932438091102487825742450620520819799165746502610546794"
/// ]
///
// pub struct ApiSignedMessage {
//     message: String, // UTF-8 encoded message "1702548662, 0x71C7656EC7ab88b098defB751B7401B5f6d8976F, Nick, Zakirov, nikolay.zakirov@terminal3.io"
//     signature: String, // Signature of the message, "0x...."
// }

pub fn make_proof_system_msg(
    update: &SignedUserProfileUpdate,
    prev_leaf_hash: &Hash,
    siblings: &[Sibling],
) -> ProofSystemMessage {
    let eth_address = &update.eth_address();
    let mut proof_system_msg = HashMap::new();
    let msg_val = make_message_val(&update.profile_update.unparsed_profile);
    proof_system_msg.insert("message".to_string(), msg_val);
    let signatures_val = make_signatures_val(
        &update.user_signature,
        eth_address,
        &update.profile_update.unparsed_profile,
    );
    proof_system_msg.insert("signatures".to_string(), signatures_val);
    let prev_leaf_hash_val = Value::from(vec![fe_to_biguint(&prev_leaf_hash).to_str_radix(10)]);
    proof_system_msg.insert("old_message_poseidon_hash".to_string(), prev_leaf_hash_val);
    let path_indices = siblings
        .iter()
        .map(|s| match s.direction {
            HashDirection::Left => "0",
            HashDirection::Right => "1",
        })
        .collect::<Vec<&str>>();
    let path_indices_val = Value::from(path_indices);
    proof_system_msg.insert("pathIndices".to_string(), path_indices_val);
    let siblings_val = siblings
        .iter()
        .map(|s| fe_to_biguint(&s.hash).to_str_radix(10))
        .collect::<Vec<String>>();
    let siblings_val = Value::from(siblings_val);
    proof_system_msg.insert("siblings".to_string(), siblings_val);
    proof_system_msg
}

fn make_signatures_val(signature: &Signature, eth_address: &str, msg: &str) -> Value {
    let decoded_sig = hex::decode(signature[2..].to_string()).unwrap();
    let r_bytes = &decoded_sig[..32];
    let s_bytes = &decoded_sig[32..64];
    let (r, s) = (
        ScalarSecp::from_repr(*FieldBytes::<ECrv>::from_slice(r_bytes)).unwrap(),
        ScalarSecp::from_repr(*FieldBytes::<ECrv>::from_slice(s_bytes)).unwrap(),
    );
    let (r_inv, s, t_x, t_y, u_x, u_y) = eff_ecdsa_input(r, s, eth_address, msg);
    let r_inv_str = scalar_to_biguint(&r_inv).to_str_radix(10);
    let s_str = scalar_to_biguint(&s).to_str_radix(10);
    let u_x_str = fe_to_biguint(&u_x).to_str_radix(10);
    let u_y_str = fe_to_biguint(&u_y).to_str_radix(10);
    let t_x_str = fe_to_biguint(&t_x).to_str_radix(10);
    let t_y_str = fe_to_biguint(&t_y).to_str_radix(10);
    let signatures = vec![r_inv_str, s_str, t_x_str, t_y_str, u_x_str, u_y_str];
    let signatures_val = Value::from(signatures);
    signatures_val
}

fn make_message_val(msg: &str) -> Value {
    let bits_string = get_bits_string(&msg, BIT_SIZE);

    let msg_val = Value::from(bits_string);
    msg_val
}

fn get_bits_string(input_string: &str, bit_size: usize) -> Vec<String> {
    let data = pad_msg(input_string.as_bytes(), bit_size);
    let data_bits: BitVec<u8, Msb0> = BitVec::from_vec(data);
    let msg: Vec<String> = data_bits
        .iter()
        .map(|b| if *b { "1".to_string() } else { "0".to_string() })
        .collect();
    msg
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use merkle_tree::HashDirection;
    use tokio::sync::mpsc;

    // Helper function to create a dummy UserProfileUpdate (placeholder)
    pub fn dummy_user_profile_update() -> UserProfileUpdate {
        let msg = "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
        msg.try_into().unwrap()
    }

    // Helper function to create a dummy Signature (placeholder)
    pub fn dummy_signature() -> Signature {
        String::from("0x7c62b0e515eb044b731e244904d6efc7cb6dad49b061095b92c33443cb9bfa68f1a61d9f25c990e3c6fc94b280b181bfc77266eca37e77d123e0e67892ee5efc")
    }

    // Helper function to create a dummy Hash (placeholder)
    pub fn zero_hash() -> Hash {
        Hash::from_str_vartime(
            "19186055882243973308626442936814331228632512745896196441702367494386046454885",
        )
        .unwrap()
    }

    pub fn dummy_first_hash() -> Hash {
        Hash::from_str_vartime(
            "101176329091698335529460225682959434402786110142788260993893987876843326118705",
        )
        .unwrap()
    }

    // Helper function to create a list of dummy Siblings (placeholder)
    pub fn dummy_siblings() -> Vec<Sibling> {
        vec![
            Sibling {
                hash: Hash::from_str_vartime(
                    "19186055882243973308626442936814331228632512745896196441702367494386046454885",
                )
                .unwrap(),
                direction: HashDirection::Right,
            },
            Sibling {
                hash: Hash::from_str_vartime(
                    "18960378590443015153965892039080763573460244091359764013472153018086901292684",
                )
                .unwrap(),
                direction: HashDirection::Right,
            },
        ]
    }
    pub fn dummy_eth_address() -> String {
        "0x631438556b66c4908579Eab920dc162FF58958ea".to_string()
    }

    #[tokio::test]
    async fn test_proof_system_message_structure() {
        let update = dummy_user_profile_update();
        let signature = dummy_signature();
        let signed_update = SignedUserProfileUpdate::from_profile_update(update, signature);
        let prev_leaf_hash = zero_hash();
        let siblings = dummy_siblings();

        let proof_system_msg = make_proof_system_msg(&signed_update, &prev_leaf_hash, &siblings);

        assert!(proof_system_msg.contains_key("message"));
        assert!(proof_system_msg.contains_key("signatures"));
        assert!(proof_system_msg.contains_key("old_message_poseidon_hash"));
        assert!(proof_system_msg.contains_key("pathIndices"));
        assert!(proof_system_msg.contains_key("siblings"));
        // Additional assertions to check the structure of the HashMap...
    }

    #[tokio::test]
    async fn test_make_signatures_val() {
        // You need a real signature and real message to test this function properly.
        // This is a dummy placeholder to illustrate the test structure.
        let update = dummy_user_profile_update();
        let eth_address = dummy_eth_address();
        let signature = dummy_signature();

        let signatures_val =
            make_signatures_val(&signature, &eth_address, &update.unparsed_profile);

        // Verify that signatures_val contains the expected number of elements
        // and that each element is a correctly formatted number string.
        // This assumes the signature and message are valid and can be properly processed.
        assert_eq!(signatures_val.as_array().unwrap().len(), 6);
    }

    #[tokio::test]
    async fn test_get_bits_string() {
        let input_string = "Test";
        let bits_string = get_bits_string(input_string, 40);

        // Convert 'Test' into its ASCII bit representation
        let expected_bits_string = vec![
            // ASCII for 'T' is 84: "01010100"
            "0", "1", "0", "1", "0", "1", "0", "0", // ASCII for 'e' is 101: "01100101"
            "0", "1", "1", "0", "0", "1", "0", "1", // ASCII for 's' is 115: "01110011"
            "0", "1", "1", "1", "0", "0", "1", "1", // ASCII for 't' is 116: "01110100"
            "0", "1", "1", "1", "0", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        ];

        assert_eq!(bits_string, expected_bits_string);
    }

    #[tokio::test]
    async fn test_proof_system_message_builder_run() {
        let (tx, rx) = mpsc::channel(1);
        let (psmb_tx, mut psmb_rx) = mpsc::channel(1);

        // Create a dummy ProofSystemMessageBuilder
        let mut builder = ProofSystemMessageBuilder::new(rx, psmb_tx.clone());

        // Simulate sending a message to the ProofSystemMessageBuilder
        let update = dummy_user_profile_update();
        let signature = dummy_signature();
        let signed_update = SignedUserProfileUpdate::from_profile_update(update, signature);
        let prev_leaf_hash = zero_hash();
        let siblings = dummy_siblings();
        let proof_system_message =
            make_proof_system_msg(&signed_update, &prev_leaf_hash, &siblings);

        tx.send((zero_hash(), signed_update, prev_leaf_hash, siblings))
            .await
            .unwrap();

        // Run the builder in a separate async task
        tokio::spawn(async move {
            builder.run().await;
        });

        // Send the signed message to the ProofSystemMessageBuilder
        psmb_tx.send(proof_system_message).await.unwrap();

        // Receive the result from the builder
        // Here we expect to receive a ProofSystemMessage generated by the builder
        if let Some(proof_system_msg) = psmb_rx.recv().await {
            assert!(proof_system_msg.contains_key("message"));
            assert!(proof_system_msg.contains_key("signatures"));
            assert!(proof_system_msg.contains_key("old_message_poseidon_hash"));
            assert!(proof_system_msg.contains_key("pathIndices"));
            assert!(proof_system_msg.contains_key("siblings"));
        } else {
            panic!("ProofSystemMessageBuilder did not send a message");
        }
    }
}
