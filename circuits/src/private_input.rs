use serde_json::Value;
use std::collections::HashMap;
use proof_system_message::proof_system_message;
pub type PrivateInput = HashMap<String, Value>;
fn push_to_private_inputs(private_inputs: &mut Vec<HashMap<String, Value>>, proof_message: ProofSystemMessage) {
    let mut private_input = HashMap::new();

    // Insert the values from ProofSystemMessage into the private_input HashMap
    for (key, value) in proof_message {
        private_input.insert(key, value);
    }

    // Push the private_input HashMap into private_inputs
    private_inputs.push(private_input);
}




fn push_from_json_to_private_input(filename: &str, private_inputs: &mut Vec<PrivateInput>) {
    // Read the JSON file
    let json_content = std::fs::read_to_string(filename).expect("Unable to read file");

    // Parse the JSON content into a Value object
    let parsed_json: Value = serde_json::from_str(&json_content).expect("Unable to parse JSON");

    // Assume the JSON is an array of objects, each object representing private inputs
    if let Value::Array(inputs) = parsed_json {
        // Iterate through each object in the JSON array
        for input in inputs {
            if let Value::Object(obj) = input {
                // Convert each object into a PrivateInput HashMap and push it into private_inputs
                private_inputs.push(obj);
            }
        }
    } else {
        println!("JSON content is not an array of objects");
    }
}



// #[cfg(test)]
// mod tests {
//     use super::*;
//     use serde_json::json;

//     #[test]
//     fn test_connect_to_private_inputs() {
//         // Create a ProofSystemMessage for testing
//         let mut proof_message = HashMap::new();
//         proof_message.insert("message".to_string(), json!("test_message"));
//         proof_message.insert("signature".to_string(), json!("test_signature"));

//         // Create an empty private_inputs vector
//         let mut private_inputs: Vec<HashMap<String, Value>> = Vec::new();

//         // Call the function
//         connect_to_private_inputs(&mut private_inputs, proof_message);

//         // Assert that private_inputs contains the inserted values
//         assert_eq!(private_inputs.len(), 1);

//         let inserted_values = private_inputs.first().unwrap();
//         assert_eq!(inserted_values.get("message"), Some(&json!("test_message")));
//         assert_eq!(inserted_values.get("signature"), Some(&json!("test_signature")));
//     }
// }
