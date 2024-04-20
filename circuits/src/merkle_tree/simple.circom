

template simple()
{
 
 
 signal input in;
 signal output out;
 log("input");
 log(in);
 out <== -in;
 
log("output");
log(out);
}

component main{ public[in]} = simple();