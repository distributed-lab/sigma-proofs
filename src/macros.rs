#[macro_export]
macro_rules! __compute_formula_constraint {
// Unbracket a statement
    (@external ($($x:tt)*)) => {
        // Add a trailing +
        __compute_formula_constraint!(@internal ( $($x)* +))
    };
    // Inner part of the formula: give a list of &Scalars
    // Since there's a trailing +, we can just generate the list as normal...
    (@internal ( $( $scalar:ident * $point:ident +)+ )) => {
        vec![ $( Term {multiplier_name: stringify!($scalar).to_string(), point_name: stringify!($point).to_string()} , )* ]
    };
}

#[macro_export]
macro_rules! define_proof {
    (
        $proof_module_name:ident // Name of the module to create
        ,
        $proof_label_string:expr // A string literal, used as a domain separator
        ,
        ( $($secret_var:ident),+ ) // Secret variables, sep by commas
        ,
        ( $($instance_var:ident),+ ) // Public instance variables, separated by commas
        ,
        ( $($common_var:ident),* ) // Public common variables, separated by commas
        :
        // List of statements to prove
        // Format: LHS = ( ... RHS expr ... ),
        $($lhs:ident = $statement:tt),+
    ) => {
        pub mod $proof_module_name {
        use crate::proof::*;
        use super::__compute_formula_constraint;
        use ark_secp256k1::{Affine, Projective, Fr, Fq};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::{Field, PrimeField, UniformRand};

        pub fn generate_template_header() -> String{
            let mut code = String::new();

            code.push_str("mod witness{\n");
            $(
                        code.push_str(&format!("    const {x}_r: Scalar = ( {{{x}_r}}, );\n", x = stringify!($secret_var)));
            )*

            code.push_str("\n");
            $(
                        code.push_str(&format!("    const {x}: Gej = ( {{{x}_x}}, {{{x}_y}}, 1);\n", x = stringify!($instance_var)));
                        code.push_str(&format!("    const {x}_r: Gej = ( {{{x}_r_x}}, {{{x}_r_y}}, 1);\n\n", x = stringify!($instance_var)));
            )*
            code.push_str("}\n\n");


            code.push_str("mod params{\n");
            $(
                        code.push_str(&format!("    const {x}: Gej = ( {{{x}_x}}, {{{x}_y}}, 1);\n", x = stringify!($common_var)));
            )*

            code.push_str("}\n");
            code

        }

        pub fn generate_template() -> String {

            let mut code = String::new();

            code.push_str(&generate_template_header());

            let mut public_var_tuple = String::new();
            let mut response_var_tuple = String::new();
            let mut instance_var_tuple = String::new();

            public_var_tuple.push_str("(");
            $(
                let _ = stringify!($common_var);
                public_var_tuple.push_str("Gej,");
            )*
            public_var_tuple.push_str(")");

            response_var_tuple.push_str("(");
            $(
                let _ = stringify!($secret_var);
                response_var_tuple.push_str("Scalar,");
            )*
            response_var_tuple.push_str(")");

            instance_var_tuple.push_str("(");
            $(
                let _ = stringify!($instance_var);
                instance_var_tuple.push_str("Gej,");
            )*
            instance_var_tuple.push_str(")");

            code.push_str("fn compute_challenge(");

            code.push_str(&format!("instance: {},", instance_var_tuple));
            code.push_str(&format!("commitments: {}) -> Scalar {{\n", instance_var_tuple));

            code.push_str("let (");
            $(
               code.push_str(&format!("{},", stringify!($instance_var)));
            )*
            code.push_str(&format!("): {} = instance;\n", response_var_tuple));
            code.push_str("let (");
            $(
               code.push_str(&format!("{}_r,", stringify!($instance_var)));
            )*
            code.push_str(&format!("): {} = commitments;\n", response_var_tuple));

            code.push_str(" let ctx: Ctx8 = jet::sha_256_ctx_8_init();\n");


            $(
                code.push_str(&format!("let ({x}_x, {x}_y): (u256, u256) = unwrap(jet::gej_normalize({x}));\n", x = stringify!($instance_var)));
                code.push_str(&format!("let ({x}_r_x, {x}_r_y): (u256, u256) = unwrap(jet::gej_normalize({x}_r));\n", x = stringify!($instance_var)));

                code.push_str(&format!("let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, {}_x);\n", stringify!($instance_var)));
                code.push_str(&format!("let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, {}_y);\n", stringify!($instance_var)));

                code.push_str(&format!("let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, {}_r_x);\n", stringify!($instance_var)));
                code.push_str(&format!("let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, {}_r_y);\n\n", stringify!($instance_var)));
            )*

            code.push_str(" jet::scalar_normalize(jet::sha_256_ctx_8_finalize(ctx))\n}\n\n");


            //fn verify batchable
            code.push_str("fn verify_proof_batchable(\n");

            code.push_str(&format!("public_vars: {},", public_var_tuple));
            code.push_str(&format!("response: {},", response_var_tuple));
            code.push_str(&format!("instance: {},", instance_var_tuple));
            code.push_str(&format!("commitments: {}) {{\n", instance_var_tuple));

            code.push_str("let (");
            $(
               code.push_str(&format!("{},", stringify!($common_var)));
            )*
            code.push_str(&format!("): {} = public_vars;\n", public_var_tuple));

            code.push_str("let (");
            $(
               code.push_str(&format!("{}_r,", stringify!($secret_var)));
            )*
            code.push_str(&format!("): {} = response;\n", response_var_tuple));

            code.push_str("let (");
            $(
               code.push_str(&format!("{},", stringify!($instance_var)));
            )*
            code.push_str(&format!("): {} = instance;\n", response_var_tuple));

            code.push_str("let (");
            $(
               code.push_str(&format!("{}_r,", stringify!($instance_var)));
            )*
            code.push_str(&format!("): {} = commitments;\n\n", instance_var_tuple));

            code.push_str("let challenge: Scalar = compute_challenge(instance,commitments);\n");

            $(
                let terms = __compute_formula_constraint!(@external $statement);
                code.push_str(&generate_constraint_code(terms, stringify!($lhs).to_string()));

                let point_name = stringify!($lhs);
                code.push_str(&format!(
                    "\nlet {point_name}_rhs: Gej = jet::scale({point_name}, challenge);\n"
                ));
                code.push_str(&format!(
                    "let {point_name}_rhs: Gej = jet::gej_add({point_name}, {point_name}_r);\n\n"
                ));

                code.push_str(&format!(
                    "assert!(jet::gej_equiv({point_name}_lhs, {point_name}_rhs));\n\n\n"
                ));
            )*
            code.push_str("}\n");

            code.push_str("fn verify_proof_compact(\n");

            code.push_str(&format!("public_vars: {},", public_var_tuple));
            code.push_str(&format!("response: {},", response_var_tuple));
            code.push_str(&format!("instance: {},", instance_var_tuple));
            code.push_str("challenge: Scalar) {\n");

            code.push_str("let (");
            $(
               code.push_str(&format!("{},", stringify!($common_var)));
            )*
            code.push_str(&format!("): {} = public_vars;\n", public_var_tuple));

            code.push_str("let (");
            $(
               code.push_str(&format!("{}_r,", stringify!($secret_var)));
            )*
            code.push_str(&format!("): {} = response;\n", response_var_tuple));

            code.push_str("let (");
            $(code.push_str(&format!("{},", stringify!($instance_var)));)*

            code.push_str(&format!("): {} = instance;\n\n", response_var_tuple));

            $(
                let terms = __compute_formula_constraint!(@external $statement);
                code.push_str(&generate_constraint_code(terms, stringify!($lhs).to_string()));

                let point_name = stringify!($lhs);
                code.push_str(&format!(
                    "\nlet {point_name}_rhs: Gej = jet::scale({point_name}, challenge);\n"
                ));
                code.push_str(&format!(
                    "let {point_name}_rhs: Gej = jet::gej_negate({point_name}_rhs);\n\n"
                ));

                code.push_str(&format!(
                    "let {point_name}_r: Gej = jet::gej_add({point_name}_lhs, {point_name}_rhs);"
                ));
            )*

            code.push_str("let compute_challenge: Scalar = compute_challenge(instance, (");
            $(
            code.push_str(&format!("{}_r,", stringify!($instance_var)));
            )*
            code.push_str("));\n");


            code.push_str("assert!(jet::eq_256(challenge, computed_challenge));\n}");

            code.push_str("fn main() {\n");
            code.push_str(&format!("let public: {} = (\n", public_var_tuple));
            $(code.push_str(&format!("params::{},", stringify!($common_var)));)*
            code.push_str(");\n");

            code.push_str(&format!("let response: {} = (\n", response_var_tuple));
            $(code.push_str(&format!("witness::{},", stringify!($secret_var)));)*
            code.push_str(");\n");

            code.push_str(&format!("let instance: {} = (\n", instance_var_tuple));
            $(code.push_str(&format!("witness::{},", stringify!($instance_var)));)*
            code.push_str(");\n");

            code.push_str(&format!("let commitments: {} = (\n", instance_var_tuple));
            $(code.push_str(&format!("witness::{}_r,", stringify!($instance_var)));)*
            code.push_str(");\n");

            code.push_str("verify_proof_batchable(public, response, instance, commitments);\n");
            code.push_str("//verify_proof_compact(public, response, instance, witness::challenge);\n");

            code.push_str("}\n");

            code
        }

        }
    };
}
