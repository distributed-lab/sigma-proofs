use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_secp256k1::{Affine, Fq, Fr, Projective};

pub struct Term {
    point_name: String,
    multiplier_name: String,
}

// TODO: use optimized jets for generator point
pub fn generate_constraint_code(mut terms: Vec<Term>, point_name: String) -> String {
    let mut code = String::new();

    if terms.is_empty() {
        return code;
    }

    // left hand side calculation
    let first_term = terms.remove(0);
    code.push_str(&format!(
        "let {point_name}_lhs: Gej = jet::scale({}, {})\n",
        first_term.multiplier_name, first_term.point_name
    ));

    while !terms.is_empty() {
        let term = terms.remove(0);
        code.push_str(&format!(
            "let {point_name}_lhs: Gej = jet::gej_add(jet::scale({}, {}), {point_name}_lhs)\n",
            term.multiplier_name, term.point_name
        ));
    }

    // right hand side calculation
    code.push_str(&format!(
        "let {point_name}_rhs: Gej = jet::scale({point_name}, challenge);\n"
    ));
    code.push_str(&format!(
        "let {point_name}_rhs: Gej = jet::gej_add({point_name}, {point_name}_r);\n"
    ));

    code.push_str(&format!(
        "assert!(jet::gej_equiv({point_name}_lhs, {point_name}_rhs)"
    ));

    code
}
