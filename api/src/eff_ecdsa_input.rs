use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::FieldBytes;
use k256::FieldElement;
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};
use std::ops::Add;
use std::ops::Mul;

use elliptic_curve::point::DecompressPoint;
use elliptic_curve::AffinePoint;
use elliptic_curve::PrimeField;
use elliptic_curve::Scalar;
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::Secp256k1;

use common::utils::bits::pad_msg;

use common::BIT_SIZE;

pub type ECrv = Secp256k1;
pub type ScalarSecp = Scalar<ECrv>;

#[inline(always)]
#[allow(dead_code)]
fn to_field_element(scalar: &Scalar<ECrv>) -> FieldElement {
    let field_elem = FieldElement::from_repr(scalar.to_repr()).unwrap();
    field_elem
}

fn coordinates_fe(point: &AffinePoint<ECrv>) -> (FieldElement, FieldElement) {
    let point_enc = point.to_encoded_point(false);
    let x = FieldElement::from_repr(*point_enc.x().unwrap()).unwrap();
    let y = FieldElement::from_repr(*point_enc.y().unwrap()).unwrap();
    (x, y)
}

/// Convert a point to biguint coordinates
///
/// Used for printing elliptic curve points in format similar to SageMath
#[inline(always)]
#[allow(dead_code)]
fn coordinates_biguint(point: &AffinePoint<ECrv>) -> (BigUint, BigUint) {
    let point_enc = point.to_encoded_point(false);
    let x = BigUint::from_bytes_be(point_enc.x().unwrap());
    let y = BigUint::from_bytes_be(point_enc.y().unwrap());
    (x, y)
}

/// Convert a field element to biguint
#[inline(always)]
pub fn fe_to_biguint(fe: &FieldElement) -> BigUint {
    let fe_bytes = fe.to_bytes();
    BigUint::from_bytes_be(&fe_bytes)
}

/// Convert a scalar to biguint
#[inline(always)]
pub fn scalar_to_biguint(scalar: &ScalarSecp) -> BigUint {
    let scalar_bytes = scalar.to_bytes();
    BigUint::from_bytes_be(&scalar_bytes)
}
pub fn hash_msg(msg: &[u8]) -> Vec<u8> {
    let msg_padded = pad_msg(msg, BIT_SIZE);
    let mut hasher = Keccak256::new();
    hasher.update(msg_padded);
    let mut hash = hasher.finalize().to_vec();
    hash.resize(32, 0);
    hash
}

/// pub_key = s∗T+U
/// eth_address = keccak256(pub_key)[12:]
pub fn eth_address_from_t_u_s(
    t_point: &AffinePoint<ECrv>,
    u_point: &AffinePoint<ECrv>,
    s: &ScalarSecp,
) -> String {
    let pub_key = t_point.mul(s).add(u_point);
    let pub_key_enc = pub_key.to_encoded_point(false);
    let pub_key_bytes = &pub_key_enc.to_bytes()[1..];
    let mut hasher = Keccak256::new();
    hasher.update(&pub_key_bytes);
    let mut hash = hasher.finalize().to_vec();
    hash.resize(32, 0);
    "0x".to_owned() + &hex::encode(hash[12..].to_vec())
}

/// 1.  Get Signature (r,s) from user wallet
/// 2.  Calculate U as Scalar Multiplication of (r^-1* msg_hash) * Generator point
/// 3.  R is a point on elliptic Curve with x-coordinate = r. So calculate that point by evaluating y^2 = x^3 + ax + b and solving Y
/// 4.  Calculate T as Scalar Multiplication of r^-1 * R
/// 5.  Output Signature as (r,s,x-cordinate of T,y-coordinate of T,x-coordiante of U,y-co-ordinate of U) or (r,s,Tx,Ty,Ux,Uy)
pub fn eff_ecdsa_input(
    r: ScalarSecp,
    s: ScalarSecp,
    eth_address: &str,
    msg: &str,
) -> (
    ScalarSecp,
    ScalarSecp,
    FieldElement,
    FieldElement,
    FieldElement,
    FieldElement,
) {
    let msg_hash_bytes = hash_msg(msg.as_bytes());
    let msg_hash_fb = FieldBytes::<ECrv>::from_slice(&msg_hash_bytes);
    let msg_hash = ScalarSecp::from_repr(*msg_hash_fb).unwrap();
    let eth_address = eth_address.to_lowercase();
    let r_inv = r.invert().unwrap();
    let neg_r_inv_mul_msg_hash = -r_inv.mul(&msg_hash);
    let u_point = AffinePoint::<ECrv>::generator()
        .mul(&neg_r_inv_mul_msg_hash)
        .to_affine();
    let (u_x, u_y) = coordinates_fe(&u_point);

    let mut r_point: AffinePoint<ECrv> =
        DecompressPoint::decompress(&r.to_repr(), 0.into()).unwrap();
    let mut t_point = r_point.mul(&r_inv).to_affine();
    let mut eth_address_derived = eth_address_from_t_u_s(&t_point, &u_point, &s);
    if eth_address_derived != eth_address {
        r_point = -r_point;
        t_point = r_point.mul(&r_inv).to_affine();
        eth_address_derived = eth_address_from_t_u_s(&t_point, &u_point, &s);
        assert_eq!(eth_address_derived, eth_address);
    }

    let (t_x, t_y) = coordinates_fe(&t_point);

    (r_inv, s, t_x, t_y, u_x, u_y)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_eff_ecdsa_input() {
        let msg = "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
        let r = ScalarSecp::from_str_vartime(
            "56261165120166374158454268280277966959443397430761390652429779824253406542440",
        )
        .unwrap();
        let s = ScalarSecp::from_str_vartime(
            "109300897562575462624585125002239105399222406801298130089837689150299547000572",
        )
        .unwrap();
        // let msg_hash = ScalarSecp::from_str_vartime(
        //     "71517195702070503047587663572059753726493644059415185349259027346457281130979",
        // )
        // .unwrap();
        let r_inv = ScalarSecp::from_str_vartime(
            "114017724214122913590239118467051101435899309075304970813397865749532525130752",
        )
        .unwrap();

        let t_x = to_field_element(
            &ScalarSecp::from_str_vartime(
                "41719470396887665143229471558085082766303441826687760870445000505413211950900",
            )
            .unwrap(),
        );
        let t_y = to_field_element(
            &ScalarSecp::from_str_vartime(
                "111106027789669394778837082818379800141467203340261839865317547451339618542016",
            )
            .unwrap(),
        );
        let u_x = to_field_element(
            &ScalarSecp::from_str_vartime(
                "2367239625682498150631314601240590209661171787055532765160660182122997281390",
            )
            .unwrap(),
        );
        let u_y = to_field_element(
            &ScalarSecp::from_str_vartime(
                "40137675072889765592725339977244239499857908555380577579363267600635477840287",
            )
            .unwrap(),
        );
        let eth_address = "0x631438556b66c4908579Eab920dc162FF58958ea";
        let (r_inv_, s_, t_x_, t_y_, u_x_, u_y_) = eff_ecdsa_input(r, s, eth_address, msg);
        assert_eq!(r_inv_, r_inv);
        assert_eq!(s_, s);
        assert_eq!(u_x_, u_x);
        assert_eq!(u_y_, u_y);
        assert_eq!(t_x_, t_x);
        assert_eq!(t_y_, t_y);
    }
    #[test]
    fn test_keccak256_padded() {
        let message_str = "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
        let message = message_str.as_bytes();
        let true_hash_hex = "0x9e1d4c5dc7c5a0196d5d516ad5918c4eeee75df2daf6b8a55434df624b6771e3";
        let true_hash = hex::decode(&true_hash_hex[2..]).unwrap();
        let hash = hash_msg(message);
        assert_eq!(hash, true_hash);
    }
    #[test]
    fn test_coordinates_biguint() {
        use num_traits::Num;
        let (x, _) = coordinates_biguint(&AffinePoint::<ECrv>::generator());
        assert_eq!(
            x,
            BigUint::from_str_radix(
                "55066263022277343669578718895168534326250603453777594175500187360389116729240",
                10
            )
            .unwrap()
        );
    }
    #[test]
    fn test_eth_address_from_t_u_s() {
        let eth_address = "0x631438556b66c4908579Eab920dc162FF58958ea".to_lowercase();
        let msg_hash = ScalarSecp::from_str_vartime(
            "71517195702070503047587663572059753726493644059415185349259027346457281130979",
        )
        .unwrap();
        let r = ScalarSecp::from_str_vartime(
            "56261165120166374158454268280277966959443397430761390652429779824253406542440",
        )
        .unwrap();
        let s = ScalarSecp::from_str_vartime(
            "109300897562575462624585125002239105399222406801298130089837689150299547000572",
        )
        .unwrap();

        let r_inv = r.invert().unwrap();
        let neg_r_inv_mul_msg_hash = -r_inv.mul(&msg_hash);
        let u_point = AffinePoint::<ECrv>::generator()
            .mul(&neg_r_inv_mul_msg_hash)
            .to_affine();

        let r_point: AffinePoint<ECrv> =
            DecompressPoint::decompress(&r.to_repr(), 0.into()).unwrap();
        let t_point = r_point.mul(&r_inv).to_affine();
        let eth_address_from_t_u_s = eth_address_from_t_u_s(&t_point, &u_point, &s);
        assert_eq!(eth_address_from_t_u_s, eth_address);
    }
}
