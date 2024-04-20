include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

//Converts Bytes stream of Binary Reprn of Ascii String to Decimal E.g 00110001 00110111 00110000 00110011 00110110 00110001 00111001 00110110 00110101 00111001 -> 	1703619659
template ascii_binary_string_to_decimal(size_of_string)
{
   var count_mod = size_of_string %8;
   //assert(count_mod =0 );
   var count_decimal = size_of_string\8;
   //log("Count Decimal",count_decimal);
  
   signal input ascii_binary_string[size_of_string];
   signal temp_out[count_decimal] ;
   signal temp1;
   signal out_temp;
   signal output out;
   var ascii_decimal_table[10] = [48,49,50,51,52,53,54,55,56,57];
   
   component per_byte_ascii_value[count_decimal];
   
   
for (var i =0; i< count_decimal; i++){
   per_byte_ascii_value[i] = Bits2Num(8);
   for (var j=0; j<8;j++){
      
   per_byte_ascii_value[i].in[8-j-1] <== ascii_binary_string[8*i+j];
   
   }

  //Convert ASCII to decimal 
  //log(per_byte_ascii_value[i].out);

 
 temp_out[i] <== (per_byte_ascii_value[i].out  - 48);
 //log(temp_out[i]);
 
 
 
}   
  
  signal temp;
  temp<-- temp_out[0]*10**9 +  temp_out[1]*10**8 + temp_out[2]*10**7 + temp_out[3]*10**6 + temp_out[4]*10**5 + temp_out[5]*10**4 + temp_out[6]*10**3 + temp_out[7]*10**2 + temp_out[8]*10 + temp_out[9]*1; 
  //log(temp);
  
  out<== temp;
  //log(out);
}

//component main{public[ascii_binary_string]} = ascii_binary_string_to_decimal(80);