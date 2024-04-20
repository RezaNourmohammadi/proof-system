
include "../../node_modules/binary/FromBinary.circom";

template test(numBits)
{
  signal input in[numBits];
  signal output out;

  var sum =0;


log("Sample Message");
  for(var i=0; i<numBits;i++)
  {
    sum = 2 **i * in[numBits-i-1];

  }
 
 log("Finite Field Representation");
  out <-- sum;
  log(out);

}

component main {public[in]} = test(256);