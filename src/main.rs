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
define_proof! {random_example, (x, r1, r2, r3, r4), (A, B, C, D), (G, H, P, T, M, K) : A = (x * G + r1 * H + r3 * T), B = (x * G + r2 * H), C = (r1 * K + r4 * T), D = (x * M + r3 * K + r4 * P)}

fn main() {
    let mut rng = rand::thread_rng();

    let G = Affine::generator();
    let H = Affine::rand(&mut rng);
    let P = Affine::rand(&mut rng);
    let T = Affine::rand(&mut rng);
    let M = Affine::rand(&mut rng);
    let K = Affine::rand(&mut rng);

    let x = Fr::rand(&mut rng);
    let r1 = Fr::rand(&mut rng);
    let r2 = Fr::rand(&mut rng);
    let r3 = Fr::rand(&mut rng);
    let r4 = Fr::rand(&mut rng);

    let prover = random_example::ProveGenerator {
        G: G,
        H: H,
        P: P,
        T: T,
        M: M,
        K: K,

        x: x,
        r1: r1,
        r2: r2,
        r3: r3,
        r4: r4
    };

    let s = prover.generate_and_evaluate();
    println!("{}", s);
}
