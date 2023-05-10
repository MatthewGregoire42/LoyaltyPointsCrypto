use pyo3::prelude::*;
use rand_core::OsRng;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;
use curve25519_dalek::digest::Update;

// Returns a compressed version of a tuple (Scalar, RistrettoPoint)
#[pyfunction]
fn elgamal_keygen() -> ([u8; 32], [u8; 32]) {
    let x: Scalar = Scalar::random(&mut OsRng);
    let h: RistrettoPoint = &x * &constants::RISTRETTO_BASEPOINT_TABLE;
    (x.to_bytes(), h.compress().to_bytes())
}

// Takes as parameters:
//      pk: a compressed RistrettoPoint
//      m:  a message to encrypt (number of loyalty points)
// Returns a compressed version of a tuple (RistrettoPoint, RistrettoPoint, Scalar)
#[pyfunction]
fn elgamal_enc(pk: [u8; 32], m: u32) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let pk = CompressedRistretto::from_slice(&pk).decompress().unwrap();
    let y: Scalar = Scalar::random(&mut OsRng);
    let g = &constants::RISTRETTO_BASEPOINT_TABLE;
    let m: Scalar = Scalar::from(m);

    let c1 = &y*g;
    let c2 = &m*g + y*pk;

    // y is a secret; it needs to be kept by the client to generate a proof
    // and then is discarded afterwards.
    (c1.compress().to_bytes(), c2.compress().to_bytes(), y.to_bytes())
}

// Takes as parameters:
//      sk: a compressed Scala
//      ct:  a compressed (RistrettoPoint, RistrettoPoint) ciphertext
// Returns the decrypted number of loyalty points
#[pyfunction]
fn elgamal_dec(sk: [u8; 32], ct: ([u8; 32], [u8; 32])) -> u32 {
    let sk = Scalar::from_bytes_mod_order(sk);
    let ct0 = CompressedRistretto::from_slice(&ct.0).decompress().unwrap();
    let ct1 = CompressedRistretto::from_slice(&ct.1).decompress().unwrap();
    let g = &constants::RISTRETTO_BASEPOINT_TABLE;
    let mg = ct1 + sk.invert() * ct0;

    let mut m: u32 = 0;

    // The result of ElGamal decryption (mg) is the value m*g. Assuming m is a small scalar,
    // we can extract it by guessing and checking different values until we find an m
    // such that mg = m*g.
    loop {
        if &Scalar::from(m) * g == mg {
            break m;
        } else {
            m += 1;
        }
    }
}

struct TxCiphertextData {
    ciphertext: (RistrettoPoint, RistrettoPoint),
    y: Scalar,
    m: u32, // TODO: need signed values of m. maybe calculate the inverse on the fly in encryption?
    public_h
}

struct CompressedTxCiphertextData {
    ciphertext: ([u8; 32], [u8; 32]),
    y: [u8; 32],
    m: u32,
    public_h: [u8; 32],
}

struct CompressedCtEqProof {
    shopper_ct: TxCiphertextData,
    barcode_ct: TxCiphertextData,
    m_z: [u8; 32],
    mp_z: [u8; 32],
    ys_z: [u8; 32],
    yb_z: [u8; 32],
}

#[pyfunction]
fn zk_ct_eq_prove(cs: ([u8; 32], [u8; 32]), cb: ([u8; 32], [u8; 32]),
                  ys: [u8; 32], yb: [u8; 32], m: u32, mp: u32, hs: [u8; 32], hb: [u8; 32]) ->
                  ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let g = &constants::RISTRETTO_BASEPOINT_TABLE;
    let cs0 = CompressedRistretto::from_slice(&cs.0).decompress().unwrap();
    let cs1 = CompressedRistretto::from_slice(&cs.1).decompress().unwrap();
    let cb0 = CompressedRistretto::from_slice(&cb.0).decompress().unwrap();
    let cb1 = CompressedRistretto::from_slice(&cb.1).decompress().unwrap();
    let ys = Scalar::from_bytes_mod_order(ys);
    let yb = Scalar::from_bytes_mod_order(yb);
    let m = Scalar::from(m);
    let mp = Scalar::from(mp);
    let hs = CompressedRistretto::from_slice(&hs).decompress().unwrap();
    let hb = CompressedRistretto::from_slice(&hb).decompress().unwrap();

    // Commitment
    let m_t = Scalar::random(&mut OsRng);
    let mp_t = Scalar::random(&mut OsRng);
    let ys_t = Scalar::random(&mut OsRng);
    let yb_t = Scalar::random(&mut OsRng);

    let cs0_t = &ys_t*g;
    let cs1_t = &mp_t*g + ys_t*hs;
    let cb0_t = &yb_t*g;
    let cb1_t = &m_t*g + yb_t*hb;
    let i_t = &m_t*g + &mp_t*g;

    // Challenge
    let mut hasher = Sha512::default();
    for elt in [cs0, cs1, cb0, cb1, cs0_t, cs1_t, cb0_t, cb1_t, i_t].iter() {
        let elt_bytes: [u8; 32] = elt.compress().to_bytes();
        hasher.update(&elt_bytes);
    }
    
    let c = Scalar::from_hash(hasher);

    // Response
    let m_z = m_t + m*c;
    let mp_z = mp_t + mp*c;
    let ys_z = ys_t + ys*c;
    let yb_z = yb_t + yb*c;

    (m_z.to_bytes(), mp_z.to_bytes(), ys_z.to_bytes(), yb_z.to_bytes())
}

fn zk_ct_eq_verify(cs: ([u8; 32], [u8; 32]), cb: ([u8; 32], [u8; 32]),
                   ys: [u8; 32], yb: [u8; 32], m: u32, mp: u32, hs: [u8; 32], hb: [u8; 32],
                   m_z: [u8; 32], mp_z: [u8; 32], ys_z: [u8; 32], yb_z: [u8; 32]) -> bool {

}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn _crypto(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(elgamal_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(elgamal_enc, m)?)?;
    m.add_function(wrap_pyfunction!(elgamal_dec, m)?)?;
    m.add_function(wrap_pyfunction!(zk_ct_eq_prove, m)?)?;
    Ok(())
}
