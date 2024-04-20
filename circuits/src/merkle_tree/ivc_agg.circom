
 
include "../eff_ecdsa_membership/eff_ecdsa_to_addr.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "keccak_test.circom";
include "ascii_binary_to_decimal.circom";
include "ethr_address_ascii_binary_to_decimal.circom";
include "../poseidon/poseidon.circom";
include "merkletreeupdate.circom";
template ivc(N_SIGS,N_DEPTH) {
   /*--------------------------------------------------------------------------
   Public Inputs  - Merkle Root, Previous Timestamp from Profile
   Private Inputs - Message, Signature, Path Indices to Leaf Node, Siblings
   Outputs        - New Merkle Root, Timestamp from Message
   ----------------------------------------------------------------------------*/


     //Step in = Things to be incremented = (State/Merkle Root, Timestamp for current version of user profile)
    signal input step_in[2];
    //Binary Representation of Message
    signal input message[N_SIGS][1024];
    //Signature = Signature  = (r^-1,s,Tx,Ty,Ux,Uy)
    signal input signatures[N_SIGS][6];
    //Generator Point of secp256k1
    signal input Gx;
    signal input Gy;
    signal input pathIndices[N_SIGS][N_DEPTH];
    signal input siblings[N_SIGS][N_DEPTH]; 
    
    signal output step_out[2];
   


   /* ---------------------------------------------------------------------------
      VERIFY INPUT SIGNATURE CORRESPONDS TO INPUT MESSAGE OR NOT 
   Step 1 = Assert U = - r^-1 * Hash(Message) * G

    ----------------------------------------------------------------------------*/
   log("r_inverse_input",signatures[0]);
   log("s_input",signatures[1]);
   log("Tx_input",signatures[2]);
   log("Ty_input",signatures[3]);
   log("Ux_input",signatures[4]);
   log("Uy_input",signatures[5]);
   for(var i =0; i<N_DEPTH; i++)
   { log("Path Indice -> ",i,"->",pathIndices[i]);

   }

   for(var i =0; i<N_DEPTH; i++)
   { log("Sibling  -> ",i,"->",siblings[i]);
   
   }
   //Hashing Binary Mesage message[1024]->msg_hash[256] 
    component msg_hash = keccak_hash_message(1024);
   for (var i=0; i<1024; i++){
    msg_hash.input_message[i] <== message[i];
    }       
    //Assert U = - r^-1 * Hash(Message) * G

    //Converting Output Binary Hash to Finite Field Element
    log("Message Hash Prime Field Repn");
signal intermidiate[256];
   for (var i = 0; i< 256/8; i++){     
  for (var j = 0; j < 8; j++) {
intermidiate[7-j+8*i] <-- msg_hash.output_hash[8*i+j];
  }    
  
}
log("Endianness Check");

 for (var k =0; k<256; k++){
    log(intermidiate[k]);
  } 
    
  var sum =0;
  signal hash_decimal;

log("Sample Message");
  for(var i=0; i<256;i++)
  {
    sum += 2 **i * intermidiate[256-i-1];

  }
 
 log("Finite Field Representation");
  hash_decimal <-- sum;
  log(hash_decimal);
    
  

     //Inermidiate variable to store r^-1
     signal inter_mul;

     //Intermidiate variable to store hash(message)*r^-1
     signal inter_mul1;

     signal inter_mul2;

     //inter_mul = r^-1
     inter_mul  <-- signatures[0] ;
     log("r_inverse",inter_mul);


     //Inter_mul1 = -r^-1 * hash(m)
     inter_mul1 <== hash_decimal * (-inter_mul);
     log("w= -r^-1 * hash(m)",inter_mul1);

     inter_mul2 <== 5827542974853635922205193225510230345443287737019294244905648782786748292217 + inter_mul1;

  component sMultU1 = Secp256k1Mul();
    sMultU1.scalar <== hash_decimal;
    sMultU1.xP <== Gx;
    sMultU1.yP <== Gy;

    //Assert U_x = -r^-1 * H(Message) * G_x
   //signatures[4] === sMultU.outX;
   
   log("sMultU1.outX",sMultU1.outX);
   
    //Assert U_Y = -r^-1 * H(Message) * G_y
   //signatures[5] === sMultU.outY;
   log("sMultU1.outY",sMultU1.outY);

   component sMultU2 = Secp256k1Mul();
                                // q - r_inverse
   sMultU2.scalar <== 115792089237316195423570985008687907852837564279074904382605163141518161494337-inter_mul;
    sMultU2.xP <== sMultU1.outX;
    sMultU2.yP <== sMultU1.outY;
log("Ux",signatures[4]);
log("sMultU2.outX",sMultU2.outX);

signatures[4] === sMultU2.outX;
signatures[5] === sMultU2.outY;


    
/*------------------------------------------------------------------------------
      EXTRACT ETHEREUM ADDRESSS FROM SIGNATURE
   Step 2 = Assert U = - r^-1 * Hash(Message) * G
   Signature = Signature  = (r,s,Tx,Ty,Ux,Uy)
 ------------------------------------------------------------------------------*/


   component ethr_addr_from_sig = EfficientECDSAToAddr();

   ethr_addr_from_sig.s  <==  signatures[1];
   ethr_addr_from_sig.Tx <==  signatures[2];
   ethr_addr_from_sig.Ty <==  signatures[3];
   ethr_addr_from_sig.Ux <==  signatures[4];
   ethr_addr_from_sig.Uy <==  signatures[5];

log("Ethereum Address from Signature Output",ethr_addr_from_sig.addr);
  
/*------------------------------------------------------------------------------
Step3:    EXTRACT ETHEREUM ADDRESS FROM MESSAGE

For now we always assume Message is of this form, we can re-work it later

Message : 1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com
Note: We assume Message has 1024 bits and the rest of the characters are NULL characters
Note:Ethreum Address is 42 characters long

First 10 bytes are Unix Epoch
11th byte is a comma
12th byte is a space
13th byte is a 0
14th byte is a x
15th byte to 54th byte is Ethereum Address
------------------------------------------------------------------------------ */
component ethr_addr_from_msg = ethr_address_ascii_binary_to_decimal();

for (var i =0; i<320; i++){
  ethr_addr_from_msg.in[i] <== message[14*8+i];
}

log("Ethereum_address_from_message",ethr_addr_from_msg.out);

//Assert Ethereum Address from Signature === Ethereum Address from Message

component ethereum_address_comparator = IsEqual();

ethereum_address_comparator.in[0] <== ethr_addr_from_msg.out;
ethereum_address_comparator.in[1] <== ethr_addr_from_sig.addr;

ethereum_address_comparator.out === 1;


  //constrain_addr.in[0] <== ethr_addr_from_msg.out;
  //constrain_addr.in[1] <== ethr_addr_from_sig.out;

  //0 === constrain_addr.out; 

 // Note : Could also do ethr_addr_from_msg.out === ethr_addr_from_sig.out
 

/*------------------------------------------------------------------------------
Step4: EXTRACT TIMESTAMP FROM MESSAGE AND CHECK IT IS GREATER THAN INPUT TIMESTAMP

For now we always assume Message is of this form, we can re-work it later

Message : 1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com
Note: We assume Message has 1024 bits and the rest of the characters are NULL characters
Note:Ethreum Address is 42 characters long

First 10 bytes are Unix Epoch

------------------------------------------------------------------------------ */
component unix_epoch_from_msg_decimal = ascii_binary_string_to_decimal(80);

for(var i=0;i<8*10;i++)
{
  unix_epoch_from_msg_decimal.ascii_binary_string[i] <== message[i];
}



component comp = GreaterThan(32);

comp.in[0] <== unix_epoch_from_msg_decimal.out;
comp.in[1] <== step_in[1];
log(unix_epoch_from_msg_decimal.out);
log(step_in[1]);
log(comp.out);


comp.out === 1; 
step_out[1] <== unix_epoch_from_msg_decimal.out;
/*------------------------------------------------------------------------------
Step5: Calculate Poseidon Hash of Message

------------------------------------------------------------------------------ */
//Convert Message to FiniteField Element
component messsage_finite_field = Bits2Num(1024);

for(var i =0; i <1024; i++)
{
  messsage_finite_field.in[i] <== message[i];


}

//Calculate Poseidon Hash of message_finite_field.out

component leaf_hash = Poseidon();

leaf_hash.inputs[0] <==  messsage_finite_field.out;
leaf_hash.inputs[1] <== 3;

log("leaf_hash ", leaf_hash.out);

//Add leaf to Merkle Tree

component merkle_update = MerkleTreeIncrement(N_DEPTH);

merkle_update.leaf <== leaf_hash.out ;

for (var i=0; i<N_DEPTH;i++)
{
merkle_update.pathIndices[i] <== pathIndices[i]; 
merkle_update.siblings[i] <== siblings[i];

}

log("New Root Hash",merkle_update.root);

step_out[0] <== merkle_update.root; 


}

component main{public[step_in,message,signatures,Gx,Gy,pathIndices,siblings]}  = ivc(2,2);