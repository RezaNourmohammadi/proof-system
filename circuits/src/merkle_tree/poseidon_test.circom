include "../poseidon/poseidon.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
template poseidon_test()
{

  signal input in[2]; 

  signal output out;

  component p1 = Poseidon();


  p1.inputs[0] <== in[0];
  p1.inputs[1] <== in[1]; 

  log("Output Poseidon Hash of ", in[0],"and" , in[1] , " is" , p1.out); 


}


component main { public[in] } = poseidon_test() ;