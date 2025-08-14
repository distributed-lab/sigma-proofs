use ark_ec::CurveGroup;
use ark_secp256k1::{Affine, Fq, Fr, Projective};

pub struct Term {
    pub point_name: String,
    pub multiplier_name: String,
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
        "let {point_name}_lhs: Gej = jet::scale({}_r, {});\n",
        first_term.multiplier_name, first_term.point_name
    ));

    while !terms.is_empty() {
        let term = terms.remove(0);
        code.push_str(&format!(
            "let {point_name}_lhs: Gej = jet::gej_add(jet::scale({}_r, {}), {point_name}_lhs);\n",
            term.multiplier_name, term.point_name
        ));
    }

    code
}

pub fn compute_constraint(terms: Vec<(Fr, Affine)>) -> Affine {
    terms
        .into_iter()
        .map(|(a, b)| b * a)
        .sum::<Projective>()
        .into_affine()
}
