#!/bin/sh

cargo build
cargo run >examples/example.simf

rustfmt +nightly examples/example.simf
