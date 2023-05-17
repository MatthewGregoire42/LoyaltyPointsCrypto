use pyo3::prelude::*;
use rand_core::OsRng;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;
use curve25519_dalek::digest::Update;

const G: &RistrettoBasepointTable = &constants::RISTRETTO_BASEPOINT_TABLE;

fn pzip(p: RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

fn puzip(p: [u8; 32]) -> RistrettoPoint {
    CompressedRistretto::from_slice(&p).decompress().unwrap()
}

fn szip(s: Scalar) -> [u8; 32] {
    s.to_bytes()
}

fn suzip(s: [u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(s)
}

// Returns a compressed version of a tuple (Scalar, RistrettoPoint)
#[pyfunction]
fn elgamal_keygen() -> ([u8; 32], [u8; 32]) {
    let x: Scalar = Scalar::random(&mut OsRng);
    let h: RistrettoPoint = &x * G;
    (szip(x), pzip(h))
}

// Takes as parameters:
//      pk: a compressed RistrettoPoint
//      m:  a message to encrypt (number of loyalty points)
// Returns a compressed version of a tuple (RistrettoPoint, RistrettoPoint, Scalar)
#[pyfunction]
fn elgamal_enc(pk: [u8; 32], m: i32) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let pk = puzip(pk);
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
    (pzip(c1), pzip(c2), szip(y))
}

// Takes as parameters:
//      sk: a compressed Scala
//      ct:  a compressed (RistrettoPoint, RistrettoPoint) ciphertext
// Returns the decrypted number of loyalty points
#[pyfunction]
fn elgamal_dec(sk: [u8; 32], ct: ([u8; 32], [u8; 32])) -> i32 {
    let sk = suzip(sk);
    let ct0 = puzip(ct.0);
    let ct1 = puzip(ct.1);
    let mg = ct1 + (Scalar::zero() - sk) * ct0;

    // The result of ElGamal decryption (mg) is the value m*g. Assuming m is a small scalar,
    // we can extract it by guessing and checking different values until we find an m
    // such that mg = m*g.
    let mut m: u32 = 0;
    loop {
        if &Scalar::from(m) * G == mg {
            break m as i32;
        } else if &(Scalar::zero() - Scalar::from(m)) * G == mg {
            break -1 * (m as i32);
        } else if m > 1000000 {
            panic!("Looping too long");
        } {
            m += 1;
        }
    }
    // TODO: what if m is negative?
}

#[pyfunction]
fn add_ciphertexts(ct0: ([u8; 32], [u8; 32]), ct1: ([u8; 32], [u8; 32])) -> ([u8; 32], [u8; 32]) {
    let ct0 = (puzip(ct0.0), puzip(ct0.1));
    let ct1 = (puzip(ct1.0), puzip(ct1.1));

    (pzip(ct0.0 + ct1.0), pzip(ct0.1 + ct1.1))
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

#[pymethods]
impl CompressedTxCiphertextData {
    #[new]
    fn new(ct: ([u8; 32], [u8; 32]), y: [u8; 32], m: i32, h: [u8; 32]) -> Self {
        CompressedTxCiphertextData {
            ciphertext: ct,
            y: y,
            m: szip(int_to_scalar(m)),
            public_h: h,
        }
    }
}

fn int_to_scalar(m: i32) -> Scalar {
    let m_pos: u32 = m.abs() as u32;
    let m_scalar = if m == m_pos as i32 { Scalar::from(m_pos) }
                   else { Scalar::zero() - Scalar::from(m_pos) };
    m_scalar
}

// impl TxCiphertextData {
//     fn compress(&self) -> CompressedTxCiphertextData {
//         CompressedTxCiphertextData {
//             ciphertext: (pzip(self.ciphertext.0),
//                          pzip(self.ciphertext.1)),
//             y: szip(self.y),
//             m: Scalar::to_bytes(&self.m),
//             public_h: pzip(self.public_h),
//         }
//     }
// }

impl CompressedTxCiphertextData {
    fn decompress(&self) -> TxCiphertextData {
        TxCiphertextData {
            ciphertext: (puzip(self.ciphertext.0),
                         puzip(self.ciphertext.1)),
            y: suzip(self.y),
            m: suzip(self.m),
            public_h: puzip(self.public_h),
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
    let mp = shopper_tx.m;
    let m = barcode_tx.m;
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
        let elt_bytes: [u8; 32] = pzip(*elt);
        hasher.update(&elt_bytes);
    }
    
    let c = Scalar::from_hash(hasher);

    // Response
    let m_z = m_t + m*c;
    let mp_z = mp_t + mp*c;
    let ys_z = ys_t + ys*c;
    let yb_z = yb_t + yb*c;

    CompressedCtEqProof {
        shopper_ct: (pzip(cs0), pzip(cs1)),
        barcode_ct: (pzip(cb0), pzip(cb1)),
        cs0_t: pzip(cs0_t),
        cs1_t: pzip(cs1_t),
        cb0_t: pzip(cb0_t),
        cb1_t: pzip(cb1_t),
        i_t: pzip(i_t),
        m_z: szip(m_z),
        mp_z: szip(mp_z),
        ys_z: szip(ys_z),
        yb_z: szip(yb_z),
        hs: pzip(hs),
        hb: pzip(hb),
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

    let cs0 = puzip(pi.shopper_ct.0);
    let cs1 = puzip(pi.shopper_ct.1);
    let cb0 = puzip(pi.barcode_ct.0);
    let cb1 = puzip(pi.barcode_ct.1);
    let cs0_t = puzip(pi.cs0_t);
    let cs1_t = puzip(pi.cs1_t);
    let cb0_t = puzip(pi.cb0_t);
    let cb1_t = puzip(pi.cb1_t);
    let i_t = puzip(pi.i_t);
    let m_z = suzip(pi.m_z);
    let mp_z = suzip(pi.mp_z);
    let ys_z = suzip(pi.ys_z);
    let yb_z = suzip(pi.yb_z);
    let hs = puzip(pi.hs);
    let hb = puzip(pi.hb);

    let check1 = G * &ys_z == cs0_t + cs0 * &c;
    let check2 = G * &mp_z + hs*&ys_z == cs1_t + cs1 * &c;
    let check3 = G * &yb_z == cb0_t + cb0 * &c;
    let check4 = G * &m_z + hb * &yb_z == cb1_t + cb1 * &c;
    let check5 = G * &m_z + G * &mp_z == i_t;

    check1 && check2 && check3 && check4 && check5
}

#[pyclass]
#[derive(Clone)]
// TODO: factor pt, ct, and h out of this proof. Should be provided separately.
// (Same goes for the other proof and values the server already knows)
struct CompressedCtDecProof {
    ct: ([u8; 32], [u8; 32]),
    pt: [u8; 32],
    h: [u8; 32],
    v_t: [u8; 32],
    w_t: [u8; 32],
    x_z: [u8; 32],
}

#[pyfunction]
fn zk_ct_dec_prove(ct: ([u8; 32], [u8; 32]), pt: i32, x: [u8; 32], h: [u8; 32]) -> CompressedCtDecProof {
    let c0 = puzip(ct.0);
    let c1 = puzip(ct.1);
    let pt = int_to_scalar(pt);
    let x = suzip(x);

    // Generate Chaum-Pedersen proof
    let u = c0;
    let v = puzip(h);
    // let w = c1 + G * &(Scalar::zero() - pt);

    // Commitment
    let x_t = Scalar::random(&mut OsRng);

    let v_t = G * &x_t;
    let w_t = u * x_t;

    // Challenge
    let mut hasher = Sha512::default();
    for elt in [c0, c1, v_t, w_t].iter() {
        let elt_bytes: [u8; 32] = pzip(*elt);
        hasher.update(&elt_bytes);
    }
    
    let c = Scalar::from_hash(hasher);

    // Response
    let x_z = x_t + x * c;

    CompressedCtDecProof {
        ct: (pzip(c0), pzip(c1)),
        pt: szip(pt),
        h: pzip(v),
        v_t: pzip(v_t),
        w_t: pzip(w_t),
        x_z: szip(x_z),
    }
}

#[pyfunction]
fn zk_ct_dec_verify(pi: CompressedCtDecProof) -> bool {
    // Recompute c
    let mut hasher = Sha512::default();
    for elt in [pi.ct.0, pi.ct.1, pi.v_t, pi.w_t].iter() {
        hasher.update(&elt);
    }
    let c = Scalar::from_hash(hasher);

    let c0 = puzip(pi.ct.0);
    let c1 = puzip(pi.ct.1);
    let pt = suzip(pi.pt);
    let h = puzip(pi.h);
    let v_t = puzip(pi.v_t);
    let w_t = puzip(pi.w_t);
    let x_z = suzip(pi.x_z);

    let v = h;
    let w = c1 + G * &(Scalar::zero() - pt);

    let check1 = G * &x_z == v_t + v * c;
    let check2 = c0 * x_z == w_t + w * c;

    check1 && check2
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn _crypto(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(elgamal_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(elgamal_enc, m)?)?;
    m.add_function(wrap_pyfunction!(elgamal_dec, m)?)?;
    m.add_function(wrap_pyfunction!(add_ciphertexts, m)?)?;
    m.add_function(wrap_pyfunction!(zk_ct_eq_prove, m)?)?;
    m.add_function(wrap_pyfunction!(zk_ct_eq_verify, m)?)?;
    m.add_function(wrap_pyfunction!(zk_ct_dec_prove, m)?)?;
    m.add_function(wrap_pyfunction!(zk_ct_dec_verify, m)?)?;
    m.add_class::<CompressedTxCiphertextData>()?;
    m.add_class::<CompressedCtEqProof>()?;
    m.add_class::<CompressedCtDecProof>()?;
    Ok(())
}
