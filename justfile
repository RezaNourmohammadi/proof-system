build:
  # circom sig_prover/src/circuits/toy.circom --r1cs --wasm --sym --output sig_prover/src/circuits/secp_secq --prime vesta
  circom-secq sig_prover/src/circuits/toy.circom --r1cs --wasm --sym --output sig_prover/src/circuits/secp_secq --prime secq256k1
  cargo build --release
