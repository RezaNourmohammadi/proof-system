include "../eff_ecdsa_membership/to_address/vocdoni-keccak/keccak.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";


template keccak_hash_message(numbits)

{
  //Input Message in Little Endian Byte Representation
  signal input input_message[numbits];

  //Output 256 bit length Keccak Hash
  signal output output_hash[256];



component keccak = Keccak(numbits, 256);
    for (var i = 0; i < numbits / 8; i += 1) {
      for (var j = 0; j < 8; j++) {
        keccak.in[8*i + j] <== input_message[8*i + (7-j)];
      }
    }
for (var i = 0; i< 256/8; i++){
var log_var [8];
  for (var j = 0; j < 8; j++) {
log_var[7-j] = keccak.out[8*i+j];
  }
  //log("Byte at",i,"th position is ");  
  for (var k =0; k<8; k++){
    //log(log_var[k]);
  }  
}

signal intermidiate[256];
for (var i = 0; i< 256/8; i++){

  for (var j = 0; j < 8; j++) {
intermidiate[7-j+8*i] <-- keccak.out[8*i+j];
  }
  //log("Byte at",i,"th position is ");  
  
}

for (var k =0; k<256; k++){
    //log(intermidiate[k]);
  }  

component message_hash_finite_field = Bits2Num(256);
 
	for (var i=0; i<256; i++)
    {
      
    message_hash_finite_field.in[i] <== intermidiate[i];
    }

    //log(message_hash_finite_field.out);	
output_hash <== keccak.out;





}

//1024 is the size of the input_message here 
//component main {public [input_message] } = keccak_hash_message(32*32);


/*
Notes: 

Q: How shall the backend send the message to the proof system?
The backend should send binary representation of Message to the proof system -> The binary representation shall be obtained following the example below
Example: Message =                          test
         Binary of Message =               01110100 01100101 01110011 01110100
		 Ascii of each char                  (116)   (101)     (115)    (116)
		 
Q: How to verify the output of keccak in CIRCOM is consistant with online tools? 


Notes: Input is  32 bytes and hexadecimal represntation of "test" followed with 28 NULLs

String : " testNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULLNULL"
Binary : 0111010001100101011100110111010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
Hex    : 7465737400000000000000000000000000000000000000000000000000000000
*/
