//! Small reproducible FFI/decision benchmark; timings are informational.
use std::{hint::black_box, time::Instant};
use synch_verified::{Scope, Shape};

fn main() {
    for grants in [0, 1, 16, 64] {
        let prefixes: Vec<_> = (0..grants).map(|i| vec![6, 1, (i % 16) as u8, 2]).collect();
        let native = Scope::new(if grants == 0 { None } else { Some(&prefixes) }, &[]);
        let path = vec![6, 1, 15, 2, 3, 4, 5, 6];
        let iterations = 100_000;
        let start = Instant::now();
        let mut accepted = 0;
        for _ in 0..iterations {
            accepted += usize::from(
                black_box(&native).admits_value(black_box(&path), Shape::Leaf(&[1, 2])),
            );
        }
        let native_ns = start.elapsed().as_nanos() / iterations;
        let start = Instant::now();
        let mut reference_accepted = 0;
        for _ in 0..iterations {
            let covered = [black_box(path.as_slice()), &[1, 2]].concat();
            reference_accepted += usize::from(
                grants == 0 || black_box(&prefixes).iter().any(|p| covered.starts_with(p)),
            );
        }
        let rust_ns = start.elapsed().as_nanos() / iterations;
        assert_eq!(accepted, reference_accepted);
        println!("grants={grants}: native={native_ns} ns/call, Rust oracle={rust_ns} ns/call");
    }
}
