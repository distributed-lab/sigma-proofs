#[macro_export]
macro_rules! __divide_into_terms {
// Unbracket a statement
    (@external ($($x:tt)*)) => {
        // Add a trailing +
        __divide_into_terms!(@internal ( $($x)* +))
    };
    // Inner part of the formula: give a list of &Scalars
    // Since there's a trailing +, we can just generate the list as normal...
    (@internal ( $( $scalar:ident * $point:ident +)+ )) => {
        vec![ $( Term {multiplier_name: stringify!($scalar).to_string(), point_name: stringify!($point).to_string()} , )* ]
    };
}

#[macro_export]
macro_rules! __compute_formula_constraint {
    // Unbracket a statement
    (($public_vars:ident, $secret_vars:ident) ($($x:tt)*)) => {
        // Add a trailing +
        __compute_formula_constraint!(($public_vars,$secret_vars) $($x)* +)
    };
    // Inner part of the formula: give a list of &Scalars
    // Since there's a trailing +, we can just generate the list as normal...
    (($public_vars:ident, $secret_vars:ident)
     $( $scalar:ident * $point:ident +)+ ) => {
        vec![ $( ($secret_vars.$scalar , $public_vars.$point), )* ]
    };
}

#[macro_export]
macro_rules! define_proof {
    (
        $proof_module_name:ident // Name of the module to create
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
        use super::{__compute_formula_constraint, __divide_into_terms};
        use ark_secp256k1::{Affine, Fr};
        use ark_ec::{AffineRepr};
        use ark_ff::{PrimeField, UniformRand, BigInteger};
        use num_bigint::BigUint;
        use sha2::{Sha256, Digest};
        use ark_std::rand::{rngs::StdRng, SeedableRng};

        #[macro_export]
        macro_rules! print_point {
            ($point:ident) => {
                {
            use hex;
            let x_bytes = $point.x().unwrap().into_bigint().to_bytes_be();
            let y_bytes = $point.y().unwrap().into_bigint().to_bytes_be();
            println!("{x}, {y}", x = hex::encode(x_bytes), y = hex::encode(y_bytes) );
            }
        }}

        pub fn generate_template_header(secrets: SecretVariables, instances: InstanceVariables, instances_rand: InstanceVariables, commons: CommonVariables, challenge: Fr) -> String{
            let mut code = String::new();



            code.push_str("mod witness{\n");

            code.push_str(&format!("    const challenge: Scalar = {};", challenge));
            $(
                        code.push_str(&format!("    const {x}_r: Scalar = {y};\n", x = stringify!($secret_var), y = secrets.$secret_var));
            )*

            code.push_str("\n");
            $(
                        code.push_str(&format!("    const {}: Gej = ( ({}, {}), 1);\n", stringify!($instance_var), instances.$instance_var.x().unwrap(), instances.$instance_var.y().unwrap()));
                        code.push_str(&format!("    const {}_r: Gej = ( ({}, {}), 1);\n\n", stringify!($instance_var), instances_rand.$instance_var.x().unwrap(), instances_rand.$instance_var.y().unwrap()));
            )*
            code.push_str("}\n\n");


            code.push_str("mod param{\n");
            $(
                        code.push_str(&format!("    const {}: Gej = ( ({}, {}), 1);\n", stringify!($common_var), commons.$common_var.x().unwrap(), commons.$common_var.y().unwrap()));
            )*

            code.push_str("}\n");
            code

        }

        pub fn generate_template_batchable() -> String {

            let SECRET_VARS = vec![$(stringify!($secret_var).to_string() + "_r"),+];
            let INSTANCE_VARS = vec![$(stringify!($instance_var).to_string()),+];
            let COMMON_VARS = vec![$(stringify!($common_var).to_string()),*];

            template_generator_batchable(
                Variables{
                    common_var: COMMON_VARS,
                    instance_var: INSTANCE_VARS,
                    secret_var: SECRET_VARS
                },
                vec![$((__divide_into_terms!(@external $statement), stringify!($lhs).to_string()),)*]
                )
        }

        pub fn generate_template_compact() -> String {

            let SECRET_VARS = vec![$(stringify!($secret_var).to_string() + "_r"),+];
            let INSTANCE_VARS = vec![$(stringify!($instance_var).to_string()),+];
            let COMMON_VARS = vec![$(stringify!($common_var).to_string()),*];

            template_generator_batchable(
                Variables{
                    common_var: COMMON_VARS,
                    instance_var: INSTANCE_VARS,
                    secret_var: SECRET_VARS
                },
                vec![$((__divide_into_terms!(@external $statement), stringify!($lhs).to_string()),)*]
                )
        }
        pub struct SecretVariables{
            $(pub $secret_var: Fr,)*
        }

        pub struct InstanceVariables{
            $(pub $instance_var: Affine,)*
        }

        pub struct CommonVariables{
            $(pub $common_var: Affine,)*
        }

        pub struct ProveGenerator{
            $(pub $secret_var: Fr,)*
            $(pub $common_var: Affine,)*
        }


        pub fn compute_challenge(instance_variables: &InstanceVariables, instance_variables_rand: &InstanceVariables) -> Fr{
            let mut hasher = Sha256::new();

            $(
                // println!("{}", hex::encode(instance_variables.$instance_var.x().unwrap().into_bigint().to_bytes_be()));
                // println!("{}", hex::encode(instance_variables.$instance_var.y().unwrap().into_bigint().to_bytes_be()));
                hasher.update(instance_variables.$instance_var.x().unwrap().into_bigint().to_bytes_be());
                hasher.update(instance_variables.$instance_var.y().unwrap().into_bigint().to_bytes_be());

                // println!("{}", hex::encode(instance_variables_rand.$instance_var.x().unwrap().into_bigint().to_bytes_be()));
                // println!("{}", hex::encode(instance_variables_rand.$instance_var.y().unwrap().into_bigint().to_bytes_be()));
                hasher.update(instance_variables_rand.$instance_var.x().unwrap().into_bigint().to_bytes_be());
                hasher.update(instance_variables_rand.$instance_var.y().unwrap().into_bigint().to_bytes_be());
            )*

            let result: [u8; 32] = hasher.finalize().into();

            // println!("{}", hex::encode(result));
            Fr::from(BigUint::from_bytes_be(&result))
        }

        impl ProveGenerator {


            pub fn generate_and_evaluate(self) -> String{
                let mut code = String::new();
                let mut rng = rand::thread_rng();
                let secret_variables = SecretVariables{
                    $($secret_var: self.$secret_var,)*
                };

                let random_variables = SecretVariables{
                    $($secret_var: Fr::rand(&mut rng),)*
                };

                let common_variables = CommonVariables{
                    $($common_var: self.$common_var,)*
                };

                let instance_variables = InstanceVariables{
                    $($lhs: compute_constraint(__compute_formula_constraint!((common_variables, secret_variables) $statement)),)*
                };


                let instance_variables_rand = InstanceVariables{
                    $($lhs: compute_constraint(__compute_formula_constraint!((common_variables, random_variables) $statement)),)*
                };
                let challenge = compute_challenge(&instance_variables, &instance_variables_rand);
                $(
                    let point = instance_variables.$instance_var;
                )*

                let s = SecretVariables{
                    $($secret_var: (random_variables.$secret_var + secret_variables.$secret_var * challenge),)*
                };


                code.push_str(&generate_template_header(s, instance_variables, instance_variables_rand, common_variables, challenge));
                code.push_str(&generate_template_batchable());
                code

            }

        }

        }
    };
}
