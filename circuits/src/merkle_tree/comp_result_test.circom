include "../../node_modules/circomlib/circuits/comparators.circom";

template test()
{
signal input in[2];
signal output out;

component comp = GreaterEqThan(32);

comp.in[0] <== in[0];
comp.in[1] <== in[1];

log("Result");
log(comp.out); 
}

component main{public[in]} = test();