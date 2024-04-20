include "../../node_modules/circomlib/circuits/bitify.circom";

template ethr_address_ascii_binary_to_decimal()
{
    //Ethereum Address is 42 characters long. Each character is a byte array => 42*8 =336    0x631438556b66c4908579Eab920dc162FF58958ea = 00110000 01111000 00110110 00110011 00110001 00110100 00110011 00111000 00110101 00110101 00110110 01100010 00110110 00110110 01100011 00110100 00111001 00110000 00111000 00110101 00110111 00111001 01000101 01100001 01100010 00111001 00110010 00110000 01100100 01100011 00110001 00110110 00110010 01000110 01000110 00110101 00111000 00111001 00110101 00111000 01100101 01100001
    //The first two characters are always 0x so we can disregard that 
  signal input in[320];

  //Output is Ethereum Address in Decimal
  signal output out;

//                            0    1     2    3      4      5    6     7     8     9   a     b     c      d     e      f
 var hex_ascii_mapping[16] = [48,  49,   50,  51,    52,    53,  54,   55,   56,   57, 97,   98,   99,   100,  101, 102];

//                                        0  1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
 var hex_ascii_mapping_upper_case[16] = [ 0, 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 65, 66, 67, 68, 69, 70];

 var sum;
 var temp_ascii = 0;
 var hex_to_decimal = 0;
 component  byte_to_ascii [40];
 
for (var j =0 ; j< 40; j++)
{
  byte_to_ascii[j] = Bits2Num(8);
for (var i = 0; i < 8; i++)
{
  //log(in[8*j+ i]);
 byte_to_ascii[j].in[8-i-1] <== in[8*j+ i];
 }
 //log("byte_to_ascii");
 //log(byte_to_ascii[j].out);

 for(var k = 0; k<16; k++){
 if( hex_ascii_mapping[k] == byte_to_ascii[j].out ){          
          temp_ascii = k; 
          //log("ascii to base 16");
          //log(temp_ascii);
 }
if( hex_ascii_mapping_upper_case[k] == byte_to_ascii[j].out ){          
          temp_ascii = k; 
          //log("ascii to base 16");
          //log(temp_ascii);
 }

}
sum += temp_ascii* 16**(40-j-1);
//log("Sum at ",j,"ith Step");
//log(sum);
}

//log("Ethereum Address in decimal ", sum);

out <-- sum;
//Retrieve ascii value of each byte and convert it to decimal
/*
for(var i =0; i<40; i++){
    
for (var j=0;j<8;j++){
byte_to_ascii.in[j] <-- in[8*i+j];
}

//Find out what ascii value is in byte_to_ascii.out and store the corresponding decimal in Sum. Using Linear Search for now, gonna replace by a more efficient search algorithm later 

for(var k = 0; k<16; k++){
 if( hex_ascii_mapping[k] == byte_to_ascii.out){          
          temp_ascii = k; 
 }
}
sum += temp_ascii* 16**(40-i-1);
}



*/
}

//component main{ public[in]} = ethr_address_ascii_binary_to_decimal();

