#![allow(non_snake_case)]

pub mod macros;
pub mod proof;

extern crate ark_ec;
extern crate ark_ff;
extern crate ark_secp256k1;
extern crate ark_std;
extern crate hex;
extern crate num_bigint;
extern crate rand;
extern crate rand_chacha;
extern crate rand_core;
extern crate seeded_random;
extern crate sha2;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_secp256k1::{Affine, Fq, Fr, Projective};
use rand::thread_rng;

use ark_std::rand::{rngs::StdRng, SeedableRng};
define_proof! {dleq, (x, r1, r2), (A, B), (G, H) : A = (x * G + r1 * H), B = (x * G + r2 * H)}

fn main() {
    let mut code = String::new();
    let mut rng = StdRng::seed_from_u64(20);

    let G = Affine::generator();
    let H = Affine::rand(&mut rng);

    let x = Fr::rand(&mut rng);
    let r1 = Fr::rand(&mut rng);
    let r2 = Fr::rand(&mut rng);
    let prover = dleq::ProveGenerator {
        x: x,
        r1: r1,
        r2: r2,
        G: G,
        H: H
    };

    let s = prover.generate_and_evaluate();
    println!("{}", s);
}
