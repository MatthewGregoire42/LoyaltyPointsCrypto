use pyo3::prelude::*;
use std::cmp::Ordering;
use std::io;
use rand_core::{RngCore, OsRng};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto:CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::collections::HashSet;

// #[derive(Debug)]
// pub struct ServerData {
    
// }

// #[derive(Debug)]
// pub struct ClientData {

// }

// impl ServerData {

// }

// impl ClientData {

// }

#[pyfunction]
fn elgamal_keygen() -> (Scalar, RistrettoPoint) {
    let x: Scalar = Scalar::random(&mut OsRng);
    let h: RistrettoPoint = &x * &constants::RISTRETTO_BASEPOINT_TABLE;
    (x, h)
}

#[pyfunction]
fn elgamal_enc(pk: RistrettoPoint, m: u32) {
    let y: Scalar = Scalar::random(&mut OsRng);
    let g: RistrettoPoint = &constants::RISTRETTO_BASEPOINT_TABLE;
    let m: Scalar = Scalar::from(m);

    // y is a secret; it needs to be kept by the client to generate a proof
    // and then is discarded afterwards.
    (y*g, m*g + y*pk, y)
}

#[pyfunction]
fn elgamal_dec(sk: Scalar, ct: (RistrettoPoint, RistrettoPoint)) -> u32 {
    let (ct0, ct1) = ct;
    let g: RistrettoPoint = &constants::RISTRETTO_BASEPOINT_TABLE;
    let mg = c1 + sk.invert() * c0;

    let mut m: u32 = 0;

    // The result of ElGamal decryption (mg) is the value m*g. Assuming m is a small scalar,
    // we can extract it by guessing and checking different values until we find an m
    // such that mg = m*g.
    loop {
        if Scalar::from(m) * g == mg {
            break m;
        } else {
            m += 1;
        }
    }
}

#[pyfunction]
fn zk_ct_eq_prove(cs, cb, ys, yb, m, mp, hs, hb) {
    let g = &constants::RISTRETTO_BASEPOINT_TABLE;
    let (cs1, cs2) = cs;
    let (cb1, cb2) = cb;

    // Commitment
    let m_t = Scalar::random(&mut OsRng);
    let mp_t = Scalar::random(&mut OsRng);
    let ys_t = Scalar::random(&mut OsRng);
    let yb_t = Scalar::random(&mut OsRng);

    let cs1_t = ys_t*g;
    let cs2_t = mp_t*g + ys_t*hs;
    let cb1_t = yb_t*g;
    let cb2_t = m_t*g + yb_t*hb;
    let i_t = m_t*g + mp_t*g;

    // Challenge
    let mut hashinput: Vec<u8> = Vec::new();
    for elt in [cs1, cs2, cb1, cb2, cs1_t, cs2_t, cb1_t, cb2_t, i_t].iter() {
        let elt_compress = elt.compress();
        hashinput.extend_from_slice(&elt.to_bytes());
    }
    
    let hashinput_bytes: &[u8] = &hashinput;
    let c = Scalar::hash_from_bytes::<Sha512>(hashinput_bytes);

    // Response
    
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn _crypto(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(elgamal_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(elgamal_enc, m)?)?;
    m.add_function(wrap_pyfunction!(elgamal_dec, m)?)?;
    Ok(())
}
