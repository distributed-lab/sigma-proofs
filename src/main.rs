pub mod macros;
pub mod proof;

define_proof! {dleq, "Com(x, r1), Com(x, r2) Proof", (x, r1, r2), (A, B), (G, H) : A = (x * G + r1 * H), B = (x * G + r2 * H)}

fn main() {
    println!("{}", dleq::generate_template());
}
