use pyo3::prelude::*;
use rand_core::OsRng;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;
use curve25519_dalek::digest::Update;
use hex::encode;

const G: &RistrettoBasepointTable = &constants::RISTRETTO_BASEPOINT_TABLE;

// Returns a compressed version of a tuple (Scalar, RistrettoPoint)
#[pyfunction]
fn elgamal_keygen() -> ([u8; 32], [u8; 32]) {
    let x: Scalar = Scalar::random(&mut OsRng);
    let h: RistrettoPoint = &x * G;
    (x.to_bytes(), h.compress().to_bytes())
}

// Takes as parameters:
//      pk: a compressed RistrettoPoint
//      m:  a message to encrypt (number of loyalty points)
// Returns a compressed version of a tuple (RistrettoPoint, RistrettoPoint, Scalar)
#[pyfunction]
fn elgamal_enc(pk: [u8; 32], m: i32) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let pk = CompressedRistretto::from_slice(&pk).decompress().unwrap();
    let y: Scalar = Scalar::random(&mut OsRng);

    // We need to convert m to a scalar
    let m_pos: u32 = m.abs() as u32;
    let m_scalar = if m == m_pos as i32 { Scalar::from(m_pos) }
                   else { Scalar::zero() - Scalar::from(m_pos) };
    // println!("m == m_pos? {}", m == m_pos as i32);

    let c1 = &y*G;
    let c2 = &m_scalar*G + y*pk;

    // println!("Actual m*g: {}", encode((&m_scalar*G).compress().to_bytes()));

    // y is a secret; it needs to be kept by the client to generate a proof
    // and then is discarded afterwards.
    (c1.compress().to_bytes(), c2.compress().to_bytes(), y.to_bytes())
}

// Takes as parameters:
//      sk: a compressed Scala
//      ct:  a compressed (RistrettoPoint, RistrettoPoint) ciphertext
// Returns the decrypted number of loyalty points
#[pyfunction]
fn elgamal_dec(sk: [u8; 32], ct: ([u8; 32], [u8; 32])) -> i32 {
    let sk = Scalar::from_bytes_mod_order(sk);
    let ct0 = CompressedRistretto::from_slice(&ct.0).decompress().unwrap();
    let ct1 = CompressedRistretto::from_slice(&ct.1).decompress().unwrap();
    let mg = ct1 + (Scalar::zero() - sk) * ct0;
    // println!("mg: {}", encode(mg.compress().to_bytes()));

    // println!("m*g: {}", encode((&Scalar::from(17u32) * G).compress().to_bytes()));

    // println!("zero: {}", encode(Scalar::zero().to_bytes()));
    // println!("zero (hopefully): {}", encode((Scalar::from(17u32) +
    //     (Scalar::zero() - Scalar::from(17u32))).to_bytes()));

    // The result of ElGamal decryption (mg) is the value m*g. Assuming m is a small scalar,
    // we can extract it by guessing and checking different values until we find an m
    // such that mg = m*g.
    let mut m: u32 = 0;
    loop {
        if &Scalar::from(m) * G == mg {
            break m as i32;
        } else if &(Scalar::zero() - Scalar::from(m)) * G == mg {
            break -1 * (m as i32);
        } else if m > 10000 {
            panic!("Looping too long");
        } {
            m += 1;
        }
    }
    // TODO: what if m is negative?
}

struct TxCiphertextData {
    ciphertext: (RistrettoPoint, RistrettoPoint),
    y: Scalar,
    m: Scalar, // TODO: need signed values of m. maybe calculate the inverse on the fly in encryption?
    public_h: RistrettoPoint
}

#[pyclass]
#[derive(Clone)]
struct CompressedTxCiphertextData {
    ciphertext: ([u8; 32], [u8; 32]),
    y: [u8; 32],
    m: [u8; 32],
    public_h: [u8; 32],
}

impl TxCiphertextData {
    fn compress(&self) -> CompressedTxCiphertextData {
        CompressedTxCiphertextData {
            ciphertext: (self.ciphertext.0.compress().to_bytes(),
                         self.ciphertext.1.compress().to_bytes()),
            y: self.y.to_bytes(),
            m: Scalar::to_bytes(&self.m),
            public_h: self.public_h.compress().to_bytes(),
        }
    }
}

impl CompressedTxCiphertextData {
    fn decompress(&self) -> TxCiphertextData {
        TxCiphertextData {
            ciphertext: (CompressedRistretto::from_slice(&self.ciphertext.0).decompress().unwrap(),
                         CompressedRistretto::from_slice(&self.ciphertext.1).decompress().unwrap()),
            y: Scalar::from_bytes_mod_order(self.y),
            m: Scalar::from_bytes_mod_order(self.m),
            public_h: CompressedRistretto::from_slice(&self.public_h).decompress().unwrap(),
        }
    }
}

#[pyclass]
#[derive(Clone)]
struct CompressedCtEqProof {
    shopper_ct: ([u8; 32], [u8; 32]),
    barcode_ct: ([u8; 32], [u8; 32]),
    hs: [u8; 32],
    hb: [u8; 32],
    cs0_t: [u8; 32],
    cs1_t: [u8; 32],
    cb0_t: [u8; 32],
    cb1_t: [u8; 32],
    i_t: [u8; 32],
    m_z: [u8; 32],
    mp_z: [u8; 32],
    ys_z: [u8; 32],
    yb_z: [u8; 32],
}

#[pyfunction]
fn zk_ct_eq_prove(shopper_tx: CompressedTxCiphertextData, barcode_tx: CompressedTxCiphertextData)
                 -> CompressedCtEqProof {
    
    let shopper_tx: TxCiphertextData = shopper_tx.decompress();
    let barcode_tx: TxCiphertextData = barcode_tx.decompress();

    let cs0 = shopper_tx.ciphertext.0;
    let cs1 = shopper_tx.ciphertext.1;
    let cb0 = barcode_tx.ciphertext.0;
    let cb1 = barcode_tx.ciphertext.1;
    let ys = shopper_tx.y;
    let yb = barcode_tx.y;
    let m = shopper_tx.m;
    let mp = barcode_tx.m;
    let hs = shopper_tx.public_h;
    let hb = barcode_tx.public_h;

    // Commitment
    let m_t = Scalar::random(&mut OsRng);
    let mp_t = Scalar::random(&mut OsRng);
    let ys_t = Scalar::random(&mut OsRng);
    let yb_t = Scalar::random(&mut OsRng);

    let cs0_t = &ys_t*G;
    let cs1_t = &mp_t*G + ys_t*hs;
    let cb0_t = &yb_t*G;
    let cb1_t = &m_t*G + yb_t*hb;
    let i_t = &m_t*G + &mp_t*G;

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

    CompressedCtEqProof {
        shopper_ct: (cs0.compress().to_bytes(), cs1.compress().to_bytes()),
        barcode_ct: (cb0.compress().to_bytes(), cb1.compress().to_bytes()),
        cs0_t: cs0_t.compress().to_bytes(),
        cs1_t: cs1_t.compress().to_bytes(),
        cb0_t: cb0_t.compress().to_bytes(),
        cb1_t: cb1_t.compress().to_bytes(),
        i_t: i_t.compress().to_bytes(),
        m_z: m_z.to_bytes(),
        mp_z: mp_z.to_bytes(),
        ys_z: ys_z.to_bytes(),
        yb_z: yb_z.to_bytes(),
        hs: hs.compress().to_bytes(),
        hb: hb.compress().to_bytes(),
    }
}

#[pyfunction]
fn zk_ct_eq_verify(pi: CompressedCtEqProof) -> bool {
    // Recompute c
    let mut hasher = Sha512::default();
    for elt in [pi.shopper_ct.0, pi.shopper_ct.1, pi.barcode_ct.0, pi.barcode_ct.1,
                pi.cs0_t, pi.cs1_t, pi.cb0_t, pi.cb1_t, pi.i_t].iter() {
        hasher.update(&elt);
    }
    let c = Scalar::from_hash(hasher);

    let cs0 = CompressedRistretto::from_slice(&pi.shopper_ct.0).decompress().unwrap();
    let cs1 = CompressedRistretto::from_slice(&pi.shopper_ct.1).decompress().unwrap();
    let cb0 = CompressedRistretto::from_slice(&pi.barcode_ct.0).decompress().unwrap();
    let cb1 = CompressedRistretto::from_slice(&pi.barcode_ct.1).decompress().unwrap();
    let cs0_t = CompressedRistretto::from_slice(&pi.cs0_t).decompress().unwrap();
    let cs1_t = CompressedRistretto::from_slice(&pi.cs1_t).decompress().unwrap();
    let cb0_t = CompressedRistretto::from_slice(&pi.cb0_t).decompress().unwrap();
    let cb1_t = CompressedRistretto::from_slice(&pi.cb1_t).decompress().unwrap();
    let i_t = CompressedRistretto::from_slice(&pi.i_t).decompress().unwrap();
    let m_z = Scalar::from_bytes_mod_order(pi.m_z);
    let mp_z = Scalar::from_bytes_mod_order(pi.mp_z);
    let ys_z = Scalar::from_bytes_mod_order(pi.ys_z);
    let yb_z = Scalar::from_bytes_mod_order(pi.yb_z);
    let hs = CompressedRistretto::from_slice(&pi.hs).decompress().unwrap();
    let hb = CompressedRistretto::from_slice(&pi.hb).decompress().unwrap();

    let check1 = G * &ys_z == cs0_t + cs0 * &c;
    let check2 = G * &mp_z + hs*&ys_z == cs1_t + cs1 * &c;
    let check3 = G * &yb_z == cb0_t + cb0 * &c;
    let check4 = G * &m_z + hb * &yb_z == cb1_t + cb1 * &c;
    let check5 = G * &m_z + G * &mp_z == i_t;

    check1 && check2 && check3 && check4 && check5
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
    m.add_function(wrap_pyfunction!(zk_ct_eq_verify, m)?)?;
    Ok(())
}
