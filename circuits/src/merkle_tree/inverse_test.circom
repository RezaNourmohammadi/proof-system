template inverse_test()
{

  signal input in;
  signal output out;

  signal Intermidiate;

  signal temp;

  Intermidiate <-- 1/in;

  out <== -Intermidiate;
 
  log("-1/r");
  log(out);

  temp <-- Intermidiate * in;
  log("r*r^-1");
  log(temp);


}

component main{public[in]} = inverse_test();