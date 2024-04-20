
 
include "../eff_ecdsa_membership/eff_ecdsa_to_addr.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "keccak_test.circom";
include "ascii_binary_to_decimal.circom";
include "ethr_address_ascii_binary_to_decimal.circom";
include "../poseidon/poseidon.circom";
include "merkletreeupdate.circom";
template ivc(N_DEPTH,N_SIGS) {
   /*--------------------------------------------------------------------------
   Public Inputs  - Merkle Root, Previous Timestamp from Profile
   Private Inputs - Message, Signature, Path Indices to Leaf Node, Siblings
   Outputs        - New Merkle Root, Timestamp from Message
   ----------------------------------------------------------------------------*/


     //Step in = Things to be incremented = (State/Merkle Root, Timestamp for current version of user profile)
    signal input step_in[2];

    //Version of profile before the update
    signal input old_message_poseidon_hash[N_SIGS][1];
    //Binary Representation of Message
    signal input message[N_SIGS][1024];
    //Signature = Signature  = (r^-1,s,Tx,Ty,Ux,Uy)
    signal input signatures[N_SIGS][6];
    //Generator Point of secp256k1
   
    signal input pathIndices[N_SIGS][N_DEPTH];
    signal input siblings[N_SIGS][N_DEPTH]; 
    
    signal output step_out[2];
   


   /* ---------------------------------------------------------------------------
      VERIFY INPUT SIGNATURE CORRESPONDS TO INPUT MESSAGE OR NOT 
   Step 1 = Assert U = - r^-1 * Hash(Message) * G

    ----------------------------------------------------------------------------*/
   
   
  /*  log("r_inverse_input",signatures[0]);
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
   
   } */
   //Hashing Binary Mesage message[1024]->msg_hash[256] 
    component msg_hash[N_SIGS];
   

    for (var i =0; i<N_SIGS;i++){
      msg_hash[i]   = keccak_hash_message(1024);
   for (var j=0; j<1024; i++){
    msg_hash[i].input_message[j] <== message[i][j];
    }       
    }
    //Assert U = - r^-1 * Hash(Message) * G

    //Converting Output Binary Hash to Finite Field Element
    log("Message Hash Prime Field Repn");
signal intermidiate[N_SIGS][256];
  for( var k =0; k < N_SIGS; k++){
   for (var i = 0; i< 256/8; i++){     
  for (var j = 0; j < 8; j++) {
intermidiate[k][7-j+8*i] <-- msg_hash[k].output_hash[8*i+j];
  }    
   }
}
/* log("Endianness Check");

 for (var k =0; k<256; k++){
    log(intermidiate[k]);
  }  */
    
  var sum =0;
  signal hash_decimal[N_SIGS];

log("Sample Message");

for (var j=0; j<N_SIGS;j++)
{
  for(var i=0; i<256;i++)
  {
    sum += 2 **i * intermidiate[j][256-i-1];

  }
 
 log("Finite Field Representation");
  hash_decimal[j] <-- sum;
  log(hash_decimal[j]);
}
  

     //Inermidiate variable to store r^-1
     signal inter_mul[N_SIGS];

     //Intermidiate variable to store hash(message)*r^-1
     signal inter_mul1[N_SIGS];

     signal inter_mul2[N_SIGS];

    for (var i =0; i< N_SIGS;i++)
     //inter_mul = r^-1
    { inter_mul[i]  <-- signatures[i*6][0] ;
     log("r_inverse",inter_mul[i]);
    
 
     //Inter_mul1 = -r^-1 * hash(m)
     inter_mul1[i] <== hash_decimal[i] * (-inter_mul[i]);
     log("w= -r^-1 * hash(m)",inter_mul1[i]);

     inter_mul2[i] <== 5827542974853635922205193225510230345443287737019294244905648782786748292217 + inter_mul1[i];

    }

  component sMultU1[N_SIGS];
  for ( var i =0; i <N_SIGS; i++)
  {sMultU1[i]= Secp256k1Mul();
    sMultU1[i].scalar <== hash_decimal[i];
    sMultU1[i].xP <== 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    sMultU1[i].yP <== 32670510020758816978083085130507043184471273380659243275938904335757337482424;

    //Assert U_x = -r^-1 * H(Message) * G_x
   //signatures[4] === sMultU.outX;
   
   log("sMultU1.outX",sMultU1[i].outX);
   
    //Assert U_Y = -r^-1 * H(Message) * G_y
   //signatures[5] === sMultU.outY;
   log("sMultU1.outY",sMultU1[i].outY);
  }
   component sMultU2[N_SIGS];

   for( var i =0; i< N_SIGS; i++ )
   {                            
   sMultU2[i] = Secp256k1Mul();
     // q - r_inverse
   sMultU2[i].scalar <== 115792089237316195423570985008687907852837564279074904382605163141518161494337-inter_mul[i];
    sMultU2[i].xP <== sMultU1[i].outX;
    sMultU2[i].yP <== sMultU1[i].outY;
log("Ux",signatures[i][6*i+4]);
log("sMultU2.outX",sMultU2[i].outX);

signatures[i][6*i+4] === sMultU2[i].outX;
signatures[i][6*i+5] === sMultU2[i].outY;
   }

    
/*------------------------------------------------------------------------------
      EXTRACT ETHEREUM ADDRESSS FROM SIGNATURE
   Step 2 = Assert U = - r^-1 * Hash(Message) * G
   Signature = Signature  = (r,s,Tx,Ty,Ux,Uy)
 ------------------------------------------------------------------------------*/


   component ethr_addr_from_sig[N_SIGS];

   for(var i = 0; i<N_SIGS;i++)
{
  ethr_addr_from_sig[i]= EfficientECDSAToAddr();
   ethr_addr_from_sig[i].s  <==  signatures[i][6*i+1];
   ethr_addr_from_sig[i].Tx <==  signatures[i][6*i+2];
   ethr_addr_from_sig[i].Ty <==  signatures[i][6*i+3];
   ethr_addr_from_sig[i].Ux <==  signatures[i][6*i+4];
   ethr_addr_from_sig[i].Uy <==  signatures[i][6*i+5];
   log("Ethereum Address from Signature Output",ethr_addr_from_sig[i].addr);
}


  
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
component ethr_addr_from_msg[N_SIGS];
for(var j=0; j<N_SIGS;j++){
  ethr_addr_from_msg[j]= ethr_address_ascii_binary_to_decimal();
for (var i =0; i<320; i++){
  ethr_addr_from_msg[j].in[i] <== message[j][14*8+i];
}

log("Ethereum_address_from_message",ethr_addr_from_msg[j].out);
}



//Assert Ethereum Address from Signature === Ethereum Address from Message

component ethereum_address_comparator[N_SIGS];

for (var i =0; i<N_SIGS; i++){
   ethereum_address_comparator[i] = IsEqual();
ethereum_address_comparator[i].in[0] <== ethr_addr_from_msg[i].out;
ethereum_address_comparator[i].in[1] <== ethr_addr_from_sig[i].addr;
ethereum_address_comparator[i].out === 1;
}



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
component unix_epoch_from_msg_decimal[N_SIGS];

for( var j =0; j<N_SIGS; j++)
{
  unix_epoch_from_msg_decimal[j]= ascii_binary_string_to_decimal(80);
for(var i=0;i<8*10;i++)
{
  unix_epoch_from_msg_decimal[j].ascii_binary_string[i] <== message[j][i];
}
}


component comp[N_SIGS];

for ( var i=0; i<N_SIGS;i++)
{
 comp[i] = GreaterThan(32);
comp[i].in[0] <== unix_epoch_from_msg_decimal[i].out;
comp[i].in[1] <== step_in[1];
log(unix_epoch_from_msg_decimal[i].out);
log(step_in[1]);
log(comp[i].out);
comp[i].out === 1; 
step_out[1] <== unix_epoch_from_msg_decimal[i].out;
}
/*------------------------------------------------------------------------------
Step4: Assert Poseidon Hash of Old Message Corresponds to Old Merkle Root

------------------------------------------------------------------------------ */


component old_leaf_comp = IsEqual();

component old_leaf_assert[N_SIGS] ;
for(var j =0; j<N_SIGS; j++){
 old_leaf_assert[j] = MerkleTreeInclusionProof(N_DEPTH);
old_leaf_assert[j].leaf <== old_message_poseidon_hash[j][0];
for (var i =0; i<N_DEPTH; i++){

old_leaf_assert[j].siblings[i] <== siblings[j][i];
old_leaf_assert[j].pathIndices[i] <== pathIndices[j][i];
}
//old_leaf_assert.root <== step_in[0];



old_leaf_comp.in[0] <== old_leaf_assert[j].root;
old_leaf_comp.in[1] <== step_in[0];

old_leaf_comp.out === 1;

}
/* 
/*------------------------------------------------------------------------------
Step6: Calculate Poseidon Hash of Message

------------------------------------------------------------------------------ */
/*Convert Message to FiniteField Element
component messsage_finite_field[N_SIGS];


for(var j =0; j<N_SIGS; j++)
{
 message_finite_field[j] = Bits2Num(1024);
for(var i =0; i <1024; i++)
{
  messsage_finite_field[j].in[i] <== message[j][i];


}
}
//Calculate Poseidon Hash of message_finite_field.out

component leaf_hash[N_SIGS];
for(var i =0; i<N_SIGS;i++){
leaf_hash [i]= Poseidon();

leaf_hash[i].inputs[0] <==  messsage_finite_field[i].out;
leaf_hash[i].inputs[1] <== 0;

log("leaf_hash ", leaf_hash[i].out);
}
//Add leaf to Merkle Tree

component merkle_update[N_SIGS];

for(var j =0; j<N_SIGS; j++)
{
merkle_update[j]= MerkleTreeIncrement(N_DEPTH);
merkle_update.leaf <== leaf_hash[j].out ;

for (var i=0; i<N_DEPTH;i++)
{
merkle_update.pathIndices[i] <== pathIndices[i]; 
merkle_update.siblings[i] <== siblings[i];

}

log("New Root Hash",merkle_update[i].root);
}
step_out[0] <== merkle_update[0].root; 


}
 */
}
component main{public[step_in]}  = ivc(2,2);