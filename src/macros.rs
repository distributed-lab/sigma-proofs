#[macro_export]
macro_rules! define_proof {
    (
        $proof_module_name:ident // Name of the module to create
        ,
        $proof_label_string:expr // A string literal, used as a domain separator
        ,
        ( $($secret_var:ident),+ ) // Secret variables, sep by commas
        ,
        ( $($instance_var:ident),* ) // Public instance variables, separated by commas
        ,
        ( $($common_var:ident),* ) // Public common variables, separated by commas
        :
        // List of statements to prove
        // Format: LHS = ( ... RHS expr ... ),
        $($lhs:ident = $statement:tt),+
    ) => {


        fn generate_template() -> String {
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

            code.push_str("}");


            code
        }
    };
}
