pragma circom 2.1.2;
include "../poseidon/poseidon.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";


 
 template poseidon_test()
 {
 signal input step_in[2];
 signal input test_hash;
 
 signal output step_out[2];
 
 signal hash;
 
component poseidon_hash = Poseidon();
 
 poseidon_hash.inputs[0] <== step_in[0];
 poseidon_hash.inputs[1] <== step_in[1];

 hash <== poseidon_hash.out;
   hash === test_hash;

step_out[0] <== step_in[0];
step_out[1] <== step_in[1]; 


log(hash);

 }
 
component main { public [ step_in ] } = poseidon_test();