pragma circom 2.0.2;

include "../eff_ecdsa_membership/to_address/zk-identity/eth.circom";


template gen_eth_address()

{

signal input pubkey[2];

signal output eth_address;

component pubKeyXBits = Num2Bits(256);
    pubKeyXBits.in <== pubkey[0];

    component pubKeyYBits = Num2Bits(256);
    pubKeyYBits.in <== pubkey[1];

     component pubToAddr = PubkeyToAddress();

    for (var i = 0; i < 256; i++) {
        pubToAddr.pubkeyBits[i] <== pubKeyYBits.out[i];
        pubToAddr.pubkeyBits[i + 256] <== pubKeyXBits.out[i];
    }

    log(pubToAddr.address);

}

component main {public [pubkey] } = gen_eth_address();
