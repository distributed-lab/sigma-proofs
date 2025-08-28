use ark_ec::CurveGroup;
use ark_secp256k1::{Affine, Fq, Fr, Projective};

pub struct Term {
    pub point_name: String,
    pub multiplier_name: String
}

pub struct Variables {
    pub secret_var: Vec<String>,
    pub common_var: Vec<String>,
    pub instance_var: Vec<String>
}

enum ProofType {
    Compact,
    Batchable
}

// TODO: use optimized jets for generator point
pub fn generate_constraint_code(
    mut terms: Vec<Term>,
    point_name: String,
    proof_type: ProofType
) -> String {
    let mut code = String::new();

    if terms.is_empty() {
        return code;
    }

    // left hand side calculation
    let first_term = terms.remove(0);
    code.push_str(&format!(
        "    let {point_name}_lhs: Gej = jet::scale({}_r, {});\n",
        first_term.multiplier_name, first_term.point_name
    ));

    while !terms.is_empty() {
        let term = terms.remove(0);
        code.push_str(&format!(
            "    let {point_name}_lhs: Gej = jet::gej_add(jet::scale({}_r, {}), {point_name}_lhs);\n",
            term.multiplier_name, term.point_name
        ));
    }

    match proof_type {
        ProofType::Batchable => {
            code.push_str(&format!(
                r#"
    let {point_name}_rhs: Gej = jet::scale(challenge, {point_name});
    let {point_name}_rhs: Gej = jet::gej_add({point_name}_r, {point_name}_rhs);

    assert!(jet::gej_equiv({point_name}_lhs, {point_name}_rhs));
"#
            ));
        }
        ProofType::Compact => {
            code.push_str(&format!(
                r#"
    let {point_name}_rhs: Gej = jet::scale(challenge, {point_name});
    let {point_name}_rhs: Gej = jet::negate({point_name}_rhs);

    let {point_name}_r: Gej = jet::gej_add({point_name}_lhs, {point_name}_rhs);
"#
            ));
        }    }

    code
}

pub fn template_base(vars: &Variables) -> String {
    let mut code = String::new();

    code.push_str(&format!(
        r#"
type Instances = ({instance_tuple});
type Response = ({response_tuple});
type Public = ({public_tuple});


fn sha_256_add_point(ctx: Ctx8, point: Gej) -> Ctx8 {{
    let (x, y): (u256, u256) = unwrap(jet::gej_normalize(point));

    let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, x);
    let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, y);

    ctx
}}


fn compute_challenge(instance: Instances, commitments: Instances) -> Scalar {{
    let ({instance_names}): Instances = instance;
    let ({commitment_names}): Instances = commitments;

    let ctx: Ctx8 = jet::sha_256_ctx_8_init();

{point_ctx}

    jet::scalar_normalize(jet::sha_256_ctx_8_finalize(ctx))
    }}

    "#,
        instance_tuple = vec!["Gej"; vars.instance_var.len()].join(", "),
        response_tuple = vec!["Scalar"; vars.secret_var.len()].join(", "),
        public_tuple = vec!["Gej"; vars.common_var.len()].join(", "),
        instance_names = vars.instance_var.join(", "),
        commitment_names = vars.instance_var.join("_r, "),
        point_ctx = vars
            .instance_var
            .clone()
            .into_iter()
            .map(|x| {
                format!(
                    r#"
    let ctx: Ctx 8 = sha_256_add_point({x});
    let ctx: Ctx 8 = sha_256_add_point({x}_r);
"#,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    ));

    code
}

pub fn template_generator_batchable(
    vars: Variables,
    constraints: Vec<(Vec<Term>, String)>
) -> String {
    let mut code = String::new();

    code.push_str(&template_base(&vars));

    code.push_str(&format!(
        r#"
fn verify_batchable(public_vars: Public, response: Response, instance: Instances, commitments: Instances) {{
    let ({public_vars}): Public = public_vars;
    let ({response}): Response = response;
    let ({instance}): Instances = instance;
    let ({commitments}): Instances = commitments;

    let challenge = compute_challenge(instance, commitments);

{constraint_code}



}}

fn main() {{
    let public_vars: Public = ({public_vars_param});
    let response: Response = ({response_vars_param});
    let instance: Instances = ({instances_vars_param});
    let commitments: Instances = ({commitments_vars_param});
    
    verify_batchable(public_vars, response, instance, commitments);
}}
    
    "#, 
    public_vars = vars.common_var.join(", "),
    response = vars.secret_var.join(", "),
    instance = vars.instance_var.join(", "),
    commitments = vars.instance_var.join("_r, "),
    constraint_code = constraints.into_iter().map(|(x,y)| generate_constraint_code(x, y, ProofType::Batchable)).collect::<Vec<_>>().join("\n"),
    public_vars_param = vars.common_var.clone().into_iter().map(|x| format!("param::{}", x)).collect::<Vec<_>>().join(", "),
    response_vars_param = vars.secret_var.clone().into_iter().map(|x|  format!("witness::{}", x)).collect::<Vec<_>>().join(", "),
    instances_vars_param = vars.instance_var.clone().into_iter().map(|x| format!("witness::{}", x)).collect::<Vec<_>>().join(", "),
    commitments_vars_param = vars.instance_var.clone().into_iter().map(|x| format!("witness::{}", x)).collect::<Vec<_>>().join(", "),
    )
);

    code
}

pub fn template_generator_compact(
    vars: Variables,
    constraints: Vec<(Vec<Term>, String)>
) -> String {
    let mut code = String::new();

    code.push_str(&template_base(&vars));

    code.push_str(&format!(
        r#"
fn verify_compact(public_vars: Public, response: Response, instance: Instances, challenge: Scalar) {{
    let ({public_vars}): Public = public_vars;
    let ({response}): Response = response;
    let ({instance}): Instances = instance;

{constraint_code}
    
    let commitments: Instances = ({commitments});

    let computed_challenge: Scalar = compute_challenge(instance, commitments;
    assert!(jet::eq_256(challenge, computed_challenge));
}}

fn main() {{
    let public_vars: Public = ({public_vars_param});
    let response: Response = ({response_vars_param});
    let instance: Instances = ({instances_vars_param});
    
    verify_compact(public_vars, response, instance, witness::challenge);
}}
    
    "#,
        public_vars = vars.common_var.join(", "),
        response = vars.secret_var.join(", "),
        instance = vars.instance_var.join(", "),
        constraint_code = constraints
            .into_iter()
            .map(|(x, y)| generate_constraint_code(x, y, ProofType::Compact))
            .collect::<Vec<_>>()
            .join("\n"),
        commitments = vars.instance_var.clone().into_iter().map(|x| format!("{}_r", x)).collect::<Vec<_>>().join(", "),
        public_vars_param = vars.common_var.clone().into_iter().map(|x| format!("param::{}", x)).collect::<Vec<_>>().join(", "),
        response_vars_param = vars.secret_var.clone().into_iter().map(|x|  format!("witness::{}", x)).collect::<Vec<_>>().join(", "),
        instances_vars_param = vars.instance_var.clone().into_iter().map(|x| format!("witness::{}", x)).collect::<Vec<_>>().join(", "),
    
    ));

    code
}

pub fn compute_constraint(terms: Vec<(Fr, Affine)>) -> Affine {
    terms
        .into_iter()
        .map(|(a, b)| b * a)
        .sum::<Projective>()
        .into_affine()
}
