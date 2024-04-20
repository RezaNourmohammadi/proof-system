 pragma circom 2.1.2;

// circomlib: https://github.com/iden3/circomlib/tree/master
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/gates.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/gates.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// spartan-ecdsa-monorepo: https://github.com/personaelabs/spartan-ecdsa
// eff_ecdsa: https://github.com/personaelabs/spartan-ecdsa/tree/main/packages/circuits/eff_ecdsa_membership
// you will need to remove 'include' statements there to avoid duplicate symbol errors with circomlib

include "../eff_ecdsa_membership/eff_ecdsa.circom";
include "batch_efficient_ecdsa_pubkey.circom";

// 10 is the batch size here. Change it to whatever you want.
component main { public [ step_in ] } = BatchEfficientECDSAPubKey(10);
