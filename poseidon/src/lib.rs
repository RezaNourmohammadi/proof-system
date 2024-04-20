pub mod k256_consts;
pub mod poseidon_k256;

use std::vec;

pub use elliptic_curve::ff::PrimeField;
use k256_consts::{MDS_MATRIX, NUM_FULL_ROUNDS, NUM_PARTIAL_ROUNDS, ROUND_CONSTANTS};

use k256::FieldElement;

pub struct PoseidonConstants<F: PrimeField> {
    pub round_keys: Vec<F>,
    pub mds_matrix: Vec<Vec<F>>,
    pub num_full_rounds: usize,
    pub num_partial_rounds: usize,
}

impl<F: PrimeField> PoseidonConstants<F> {
    pub fn new(
        round_constants: Vec<F>,
        mds_matrix: Vec<Vec<F>>,
        num_full_rounds: usize,
        num_partial_rounds: usize,
    ) -> Self {
        Self {
            num_full_rounds,
            num_partial_rounds,
            mds_matrix,
            round_keys: round_constants,
        }
    }
}
impl Default for PoseidonConstants<FieldElement> {
    fn default() -> Self {
        Self {
            round_keys: ROUND_CONSTANTS.to_vec(),
            mds_matrix: vec![
                MDS_MATRIX[0].to_vec(),
                MDS_MATRIX[1].to_vec(),
                MDS_MATRIX[2].to_vec(),
            ],
            num_full_rounds: NUM_FULL_ROUNDS,
            num_partial_rounds: NUM_PARTIAL_ROUNDS,
        }
    }
}

pub struct Poseidon<F: PrimeField> {
    pub state: [F; 3],
    pub constants: PoseidonConstants<F>,
    pub pos: usize,
}

impl<F: PrimeField> Poseidon<F> {
    pub fn new(constants: PoseidonConstants<F>) -> Self {
        let state = [F::ZERO; 3];
        Self {
            state,
            constants,
            pos: 0,
        }
    }

    pub fn hash(&mut self, input: &[F; 2]) -> F {
        // add the domain tag
        let domain_tag = F::from(3); // 2^arity - 1
        let input = [domain_tag, input[0], input[1]];

        self.state = input;

        let full_rounds_half = self.constants.num_full_rounds / 2;

        // First half of full rounds
        for _ in 0..full_rounds_half {
            self.full_round();
        }

        // Partial rounds
        for _ in 0..self.constants.num_partial_rounds {
            self.partial_round();
        }

        // Second half of full rounds
        for _ in 0..full_rounds_half {
            self.full_round();
        }

        self.state[1]
    }

    fn add_constants(&mut self) {
        // Add round constants
        for i in 0..self.state.len() {
            self.state[i] += self.constants.round_keys[i + self.pos];
        }
    }

    // MDS matrix multiplication
    fn matrix_mul(&mut self) {
        let mut result = [F::ZERO; 3];

        for (i, val) in self.constants.mds_matrix.iter().enumerate() {
            let mut tmp = F::ZERO;
            for (j, element) in self.state.iter().enumerate() {
                tmp += val[j] * element
            }
            result[i] = tmp;
        }

        self.state = result;
    }

    fn full_round(&mut self) {
        let t = self.state.len();
        self.add_constants();

        // S-boxes
        for i in 0..t {
            self.state[i] = self.state[i].pow_vartime(&[5, 0, 0, 0]);
        }

        self.matrix_mul();

        // Update the position of the round constants that are added
        self.pos += self.state.len();
    }

    fn partial_round(&mut self) {
        self.add_constants();

        // S-box
        self.state[0] = self.state[0].pow_vartime(&[5, 0, 0, 0]);

        self.matrix_mul();

        // Update the position of the round constants that are added
        self.pos += self.state.len();
    }
}

impl Default for Poseidon<FieldElement> {
    fn default() -> Self {
        let constants = PoseidonConstants::<FieldElement>::default();
        Self::new(constants)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k256() {
        let input: [FieldElement; 2] = [
            FieldElement::from_str_vartime("1234567").unwrap(),
            FieldElement::from_str_vartime("109987").unwrap(),
        ];

        let mut poseidon = Poseidon::default();

        let digest = poseidon.hash(&input);
        let circom_digest = FieldElement::from_str_vartime(
            "67347608691210238873822076828904934444883748683614469947191157221339123775556",
        )
        .unwrap();

        assert_eq!(digest.normalize(), circom_digest.normalize());
    }

    #[test]
    fn test_k256_2() {
        let input: [FieldElement; 2] = [
            FieldElement::from_str_vartime(
                "67347608691210238873822076828904934444883748683614469947191157221339123775556",
            )
            .unwrap(),
            FieldElement::from_str_vartime(
                "19186055882243973308626442936814331228632512745896196441702367494386046454885",
            )
            .unwrap(),
        ];
        let mut poseidon = Poseidon::default();

        let digest = poseidon.hash(&input);
        let circom_digest = FieldElement::from_str_vartime(
            "11566692650015803081426636548629035653091338896989006689963568180018809078906",
        )
        .unwrap();

        assert_eq!(digest.normalize(), circom_digest.normalize());
    }

    #[test]
    fn test_zero_and_zero() {
        let input: [FieldElement; 2] = [
            FieldElement::from_str_vartime("0").unwrap(),
            FieldElement::from_str_vartime("0").unwrap(),
        ];

        let mut poseidon = Poseidon::default();

        let digest = poseidon.hash(&input).normalize();
        println!("digest: {:?}", digest);
        let circom_digest = FieldElement::from_str_vartime(
            "19186055882243973308626442936814331228632512745896196441702367494386046454885",
        )
        .unwrap()
        .normalize();
        assert_eq!(digest, circom_digest);
    }
    #[test]
    fn test_zero_and_msg_bits_to_num() {
        let input: [FieldElement; 2] = [
            FieldElement::from_str_vartime(
                "50467092447239822034849888129708312445849210167791970035737796139738610486631",
            )
            .unwrap(),
            FieldElement::from(0),
        ];

        let mut poseidon = Poseidon::default();

        let digest = poseidon.hash(&input).normalize();
        println!("digest: {:?}", digest);
        let circom_digest = FieldElement::from_str_vartime(
            "101176329091698335529460225682959434402786110142788260993893987876843326118705",
        )
        .unwrap()
        .normalize();
        assert_eq!(digest, circom_digest);
    }
    /*
    #[test]
    fn test_bls() {
        use blstrs;
        use neptune::poseidon::{
            Poseidon as NeptunePoseidon, PoseidonConstants as NeptuneConstants,
        };
        use typenum::U2;

        type Scalar = blstrs::Scalar;
        let input = vec![Scalar::one(), Scalar::zero()];

        // Generate constants using Neptune
        let nep_constants = NeptuneConstants::<Scalar, U2>::new();
        let mut net_poseidon = NeptunePoseidon::<Scalar>::new_with_preimage(&input, &nep_constants);
        let np_digest = net_poseidon.hash();

        // Plug constants generated by Neptune into our Poseidon impl
        let constants = PoseidonConstants::<Scalar>::new(
            nep_constants.round_constants.unwrap(),
            nep_constants.mds_matrices.m,
            nep_constants.full_rounds,
            nep_constants.partial_rounds,
        );

        let mut poseidon = Poseidon::new(constants);
        let digest = poseidon.hash(input);

        // Check that the two implementations produce the same output
        assert_eq!(digest, np_digest);
    }
     */
}
