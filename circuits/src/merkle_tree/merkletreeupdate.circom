// Refer to:
// https://github.com/peppersec/tornado-mixer/blob/master/circuits/merkleTree.circom
// https://github.com/appliedzkp/semaphore/blob/master/circuits/circom/semaphore-base.circom

include "../../node_modules/circomlib/circuits/mux1.circom";
include "../poseidon/poseidon.circom";

/**
 *  MerkleTreeInclusionProof
 *  ========================
 *  
 *  Copy of the Merkle Tree implementation in Semaphore:
 *  https://github.com/semaphore-protocol/semaphore/blob/main/packages/circuits/tree.circom
 *  Instead of using the circomlib Poseidon, we use our own implementation which
 *  uses constants specific to the secp256k1 curve.
 */
template MerkleTreeInclusionProof(nLevels) {
    signal input leaf;
    signal input pathIndices[nLevels];
    signal input siblings[nLevels];

    signal output root;

    component poseidons[nLevels];
    component mux[nLevels];

    signal hashes[nLevels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < nLevels; i++) {
        //Should be 0 or 1
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        poseidons[i] = Poseidon();
        mux[i] = MultiMux1(2);

        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== siblings[i];

        mux[i].c[1][0] <== siblings[i];
        mux[i].c[1][1] <== hashes[i];

        mux[i].s <== pathIndices[i];

        poseidons[i].inputs[0] <== mux[i].out[0];
        poseidons[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== poseidons[i].out;
    }

    root <== hashes[nLevels];
}

template LeafExists(levels){
  // Ensures that a leaf exists within a merkletree with given `root`

  // levels is depth of tree
  signal input leaf;

  signal  input path_elements[levels][1];
  signal  input path_index[levels];

  signal input root;

  component merkletree = MerkleTreeInclusionProof(levels);
  merkletree.leaf <== leaf;
  for (var i = 0; i < levels; i++) {
    merkletree.path_index[i] <== path_index[i];
    merkletree.path_elements[i][0] <== path_elements[i][0];
  }

  root === merkletree.root;
}


template MerkleTreeIncrement(nLevels) {
    signal input leaf;
    signal input pathIndices[nLevels];
    signal input siblings[nLevels];

    signal output root;

    component poseidons[nLevels];
    component mux[nLevels];

    signal hashes[nLevels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < nLevels; i++) {
        //Should be 0 or 1
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        poseidons[i] = Poseidon();
        mux[i] = MultiMux1(2);

        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== siblings[i];

        mux[i].c[1][0] <== siblings[i];
        mux[i].c[1][1] <== hashes[i];

        mux[i].s <== pathIndices[i];

        poseidons[i].inputs[0] <== mux[i].out[0];
        poseidons[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== poseidons[i].out;
    }

    root <== hashes[nLevels];
    log(root);
}