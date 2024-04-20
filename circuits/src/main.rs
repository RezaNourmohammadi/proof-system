use std::{
    collections::HashMap,
    env::current_dir,
    time::{Duration, Instant},
};

use ff::PrimeField;
use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F, S,
};

use nova_snark::{
    provider::secp_secq::secp256k1, provider::secp_secq::secq256k1, traits::Group, CompressedSNARK,
};

use serde::{Deserialize, Serialize};
use serde_json::json;
#[derive(Serialize, Deserialize)]
struct IVC {
    start_pub_input: [String; 2],
    old_message_poseidon_hash: Vec<[String; 1]>,
    #[serde(
        deserialize_with = "deserialize_long_array_of_strings",
        serialize_with = "serialize_long_array_of_strings"
    )]
    message: Vec<[String; 1024]>,
    signatures: Vec<[String; 6]>,

    #[serde(alias = "pathIndices")]
    pathindices: Vec<[String; 2]>,
    siblings: Vec<[String; 2]>,
}

fn deserialize_long_array_of_strings<'de, D>(
    deserializer: D,
) -> Result<Vec<[String; 1024]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let vs: Vec<Vec<String>> = Deserialize::deserialize(deserializer)?;
    let mut res = Vec::new();

    for v in vs {
        let mut a: [String; 1024] = core::array::from_fn(|_| String::new());

        for (i, e) in v.iter().enumerate() {
            a[i] = e.clone();
        }
        res.push(a)
    }
    Ok(res)
}

fn serialize_long_array_of_strings<S>(
    input: &Vec<[String; 1024]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut res = Vec::new();
    for arr in input {
        let v: Vec<String> = arr.iter().map(|e| e.clone()).collect();
        res.push(v);
    }
    res.serialize(serializer)
}

fn run(r1cs_path: String, wasm_path: String) -> (Duration, Duration) {
    /*
    1. Define the curve cycle that we want to use.
    We will use the secq/secp curve cycle for performant ECDSA signatures.

    secp256k1 ECDSA signature verifcation operates over Scalar field of secp256K1 which is prime field of secq256k1

    */
    type G1 = secq256k1::Point;
    type G2 = secp256k1::Point;
    /*
    2. Load the r1cs and witness generator files.
    */
    let root = current_dir().unwrap();
    let circuit_file = root.join(r1cs_path);
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
    let witness_generator_wasm = root.join(wasm_path);
    let ivcs: IVC = serde_json::from_str(include_str!("../data/ivc1.json")).unwrap();
    /*
    3. Set the starting public inputs that we are going to use
    */
    let start_public_input = vec![
        F::<G1>::from_str_vartime(&ivcs.start_pub_input[0]).unwrap(),
        F::<G1>::from_str_vartime(&ivcs.start_pub_input[1]).unwrap(),
    ];
    /* 4.  Setuping the private auxiliary inputs that we will
    use when folding. */
    let mut private_inputs = Vec::new();

    // // Inserting the "messages" field into the private_inputs HashMap
    // private_inputs.insert("messages".to_string(), json!(ivcs.message[0..1024]));
    let iteration_count = 2;

    let mut private_input = HashMap::new();

    for i in 0..iteration_count {
        // TODO: Ashu. Addressing vecs, arrays by index is an antipatten. You should change
        // the input.json so that it has [ {msg: ..., sig: ...}, {msg: ..., sig: ...} ]
        // instead of { [msg1, msg2], [sig1], [sig2], ...}
        private_input.insert(
            "old_message_poseidon_hash".to_string(),
            json!(ivcs.old_message_poseidon_hash[i]),
        );
        private_input.insert("message".to_string(), json!(ivcs.message[i].as_slice()));
        private_input.insert("signatures".to_string(), json!(ivcs.signatures[i]));

        // private_input.insert("Gx".to_string(), json!(ivcs.gx));
        //private_input.insert("Gy".to_string(), json!(ivcs.gy));
        private_input.insert("pathIndices".to_string(), json!(ivcs.pathindices[i]));
        private_input.insert("siblings".to_string(), json!(ivcs.siblings[i]));

        private_inputs.push(private_input.clone());
        // drain the hashmap for security purposes
        let _ = private_input.drain();
    }
    //private_inputs.push(private_input.clone());                                 // private_inputs.push(private_input.clone());
   /* for (index, input) in private_inputs.iter().enumerate() {
        println!("Private input {}: {:?}", index, input);
    }
 */
    /*
    5. Create the public  parameters for the recursive snark.
    */
    let pp = create_public_params::<G1, G2>(r1cs.clone());

    /*
    6. We can print some info about the recursive snark that we are building
    */
    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );
    println!("Creating a RecursiveSNARK...");
    /*
    7. Create the recursive snark.
    */
    let start = Instant::now();
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_wasm),
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    let prover_time = start.elapsed();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());

    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];
    /*
    8. Verify it
    */
    //
    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(&pp, iteration_count, &start_public_input, &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    let verifier_time = start.elapsed();
    assert!(res.is_ok());
    /*
    9. The proof is quite large... so we will compress it
    . Generate a compressed snark using SPARTAN
    */
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let start = Instant::now();
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    /*
    10. Verify the compressed snark
    */
    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.to_vec(),
        z0_secondary.to_vec(),
    );
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    (prover_time, verifier_time)
}

fn main() {
    let circuit_filepath = format!("src/merkle_tree/ivc.r1cs");
    let witness_gen_filepath = format!("src/merkle_tree/ivc_js/ivc.wasm");
    run(circuit_filepath, witness_gen_filepath);
}
