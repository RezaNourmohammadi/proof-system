pragma circom 2.1.2;
include "../poseidon/poseidon.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

template merkle_init(depth)
{

var num_leaves = 2**depth;
signal input message[num_leaves][1024];
//Outputs Merkle Root
signal output out;

component message_finite_field[num_leaves];
//Convert Message to Finite Field Element


for(var i=0;i<num_leaves;i++){
    message_finite_field[i] = Bits2Num(1024);
  
    for(var j=0; j<1024;j++){

    message_finite_field[i].in[j] <== message[i][j];
     }
   log("Num2Bits Message");
   log(message_finite_field[i].out);
}

//Poseidon Hash of all the Messages

component leaf_hash[num_leaves];
for (var i =0; i<num_leaves;i++)
{
leaf_hash[i] = Poseidon();
leaf_hash[i].inputs[0] <== message_finite_field[i].out;
leaf_hash[i].inputs[1] <== 0;
log(leaf_hash[i].out);
}

//Only init for depth=2 now, will re-write the logic later

component depth_1_hash[2];

depth_1_hash[0] = Poseidon();

depth_1_hash[0].inputs[0] <== leaf_hash[0].out;
depth_1_hash[0].inputs[1] <== leaf_hash[1].out;
log("Hash AB",depth_1_hash[0].out);

depth_1_hash[1] = Poseidon();
depth_1_hash[1].inputs[0] <== leaf_hash[2].out;
depth_1_hash[1].inputs[1] <== leaf_hash[2].out;
log("Hash CD",depth_1_hash[1].out);


component merkle_root;
merkle_root= Poseidon();


merkle_root.inputs[0] <== depth_1_hash[0].out;
merkle_root.inputs[1] <== depth_1_hash[1].out;

log("Hash ABCD",merkle_root.out);

out <== merkle_root.out;

}




component main{ public [message]} = merkle_init(2);