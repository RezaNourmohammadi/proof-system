use bitvec::prelude::*;
use k256::FieldElement;
use num_bigint::BigUint;

/// This function replicates following Circom code:
/// template Bits2Num(n) {
///     signal input in[n];
///     signal output out;
///     var lc1=0;
///     var e2 = 1;
///     for (var i = 0; i<n; i++) {
///         lc1 += in[i] * e2;
///         e2 = e2 + e2;
///     }
///     lc1 ==> out;
/// }
pub fn bits2num(data: &[u8]) -> FieldElement {
    let data_bits: BitVec<u8, Msb0> = BitVec::from_vec(data.to_vec());
    let mut num = FieldElement::ZERO;
    let mut e2 = FieldElement::ONE;
    let two = FieldElement::from(2);
    for i in 0..data_bits.len() {
        if data_bits[i] {
            num += &e2;
        }
        e2 *= two;
    }
    num.normalize()
}
pub fn bits2num_bigint(data: &[u8], mod_p: BigUint) -> BigUint {
    let data_bits: BitVec<u8, Msb0> = BitVec::from_vec(data.to_vec());
    let mut num = BigUint::from(0u8);
    let mut e2 = BigUint::from(1u8);
    let two = BigUint::from(2u8);
    for i in 0..data_bits.len() {
        if data_bits[i] {
            num = (num + &e2) % &mod_p;
        }
        e2 = (e2 * &two) % &mod_p;
    }
    num
}
pub fn pad_msg(msg: &[u8], bit_size: usize) -> Vec<u8> {
    let iter = vec![0u8; bit_size / 8 - msg.len()];
    let mut msg_padded = msg.to_vec();
    msg_padded.extend(iter);
    msg_padded
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use elliptic_curve::PrimeField;

    use super::*;
    #[test]
    fn test_bits2num() {
        let input_string =
        "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
        let expected_num = BigUint::from_str(
            "50467092447239822034849888129708312445849210167791970035737796139738610486631",
        )
        .unwrap();
        let data = input_string.bytes().collect::<Vec<u8>>();
        let num = BigUint::from_bytes_be(&bits2num(&data).to_bytes());
        assert_eq!(expected_num, num);
    }
    #[test]
    fn test_bits2num2() {
        let input_string =
        "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
        let padded_input_string = pad_msg(input_string.as_bytes(), 1024);
        let expected_num = FieldElement::from_str_vartime(
            "50467092447239822034849888129708312445849210167791970035737796139738610486631",
        )
        .unwrap()
        .normalize();
        // let data = input_string.bytes().collect::<Vec<u8>>();
        let num = bits2num(&padded_input_string).normalize();
        assert_eq!(expected_num, num);
    }
    #[test]
    fn test_bits2num_biguint() {
        let input_string =
        "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
        let expected_num = BigUint::from_str(
            "50467092447239822034849888129708312445849210167791970035737796139738610486631",
        )
        .unwrap();

        let data = input_string.bytes().collect::<Vec<u8>>();
        let num = bits2num_bigint(
            &data,
            BigUint::from_str(
                "115792089237316195423570985008687907853269984665640564039457584007908834671663",
            )
            .unwrap(),
        );
        assert_eq!(expected_num, num);
    }

    #[test]
    fn test_bitvec() {
        let input_string = "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
        let data = input_string.bytes().collect::<Vec<u8>>();
        let data_bits: BitVec<u8, Msb0> = BitVec::from_vec(data.clone());
        let bits_string = "0011000100110111001100000011001100110100001101010011100100111001001100010011000000101100001000000011000001111000001101100011001100110001001101000011001100111000001101010011010100110110011000100011011000110110011000110011010000111001001100000011100000110101001101110011100101000101011000010110001000111001001100100011000001100100011000110011000100110110001100100100011001000110001101010011100000111001001101010011100001100101011000010010110000100000010000100111001001100001011001000010110000100000010100000110100101110100011101000010110000100000011000100111001001100001011001000010111001110000011010010111010001110100010000000110011101101101011000010110100101101100001011100110001101101111011011010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let mut true_bits: BitVec<u8, Msb0> = BitVec::new();
        let _ = bits_string.chars().map(|c| {
            if c == '0' {
                true_bits.push(false);
            } else {
                true_bits.push(true);
            }
        });

        let mut data_bits_iter = data_bits.iter();
        for true_bit in true_bits.iter() {
            let next_bit = data_bits_iter.next().unwrap();
            assert_eq!(true_bit, next_bit);
        }
    }
    #[test]
    fn test_pad_msg() {
        let message_str = "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
        let message = message_str.as_bytes();
        let padded_message = pad_msg(message, 1024);
        let expected_padded_message = b"1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(padded_message.len(), 1024 / 8);
        assert_eq!(padded_message, expected_padded_message);
    }
}
