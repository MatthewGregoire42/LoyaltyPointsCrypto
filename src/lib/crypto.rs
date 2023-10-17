use rand_core::OsRng;
use rand::rngs;
use std::collections::HashMap;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{RistrettoPoint, RistrettoBasepointTable, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha256, Sha512, Digest};
use curve25519_dalek::digest::Update;
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce
};
use generic_array::typenum::U12;
use generic_array;
use lazy_static::lazy_static;

const MAX_POINTS: u32 = 100000;

pub(crate) const G: &RistrettoBasepointTable = &constants::RISTRETTO_BASEPOINT_TABLE;

fn create_dlog_table() -> HashMap<[u8; 32], i32> {
    let mut table = HashMap::new();

    let m = (MAX_POINTS as f32).sqrt() as i32 + 1;
    for i in 0..m {
        let k = pzip(&int_to_scalar(i)*G);
        table.insert(k, i);
    }

    table
}

lazy_static! {
    static ref DLOG_TABLE: HashMap<[u8; 32], i32> = create_dlog_table();
}

type Point = RistrettoPoint;
type Ciphertext = (Point, Point);

pub(crate) fn h_point() -> Point {
    RistrettoPoint::hash_from_bytes::<Sha512>("base h".as_bytes())
}

fn u_point() -> Point {
    RistrettoPoint::hash_from_bytes::<Sha512>("base u".as_bytes())
}

pub(crate) fn pzip(p: Point) -> [u8; 32] {
    p.compress().to_bytes()
}

pub(crate) fn puzip(p: [u8; 32]) -> Point {
    CompressedRistretto::from_slice(&p).decompress().unwrap()
}

pub(crate) fn elgamal_keygen() -> (Scalar, Point) {
    let x: Scalar = Scalar::random(&mut OsRng);
    let h: Point = &x * G;
    (x, h)
}

pub(crate) fn elgamal_enc(pk: Point, m: Point) -> Ciphertext {
    let r = Scalar::random(&mut OsRng);
    let c1 = &r*G;
    let c2 = &r*pk + m;

    (c1, c2)
}

// Takes as parameters:
//      sk: a compressed Scalar
//      ct:  a compressed (Point, Point) ciphertext
// Returns the decrypted chosen mask
pub(crate) fn elgamal_dec(sk: Scalar, ct: Ciphertext) -> Point {
    ct.1 + (Scalar::zero() - sk) * ct.0
}

pub(crate) fn encrypt(pk: Point, m: [u8; 32]) -> (Ciphertext, Vec<u8>, Nonce<U12>) {
    // Choose random point p to encrypt with ElGamal. H(p) is the symmetric key
    // (we model H as a random oracle)
    let p = Point::random(&mut OsRng);
    let ct = elgamal_enc(pk, p);

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, pzip(p));
    let k = hasher.finalize();

    let cipher = Aes256Gcm::new(&k);
    let nonce = Aes256Gcm::generate_nonce(&mut rngs::OsRng);
    let sym_ct = cipher.encrypt(&nonce, m.as_ref());

    let sym_ct = match sym_ct {
        Ok(ct) => ct,
        Err(_) => panic!("Symmetric encryption failed")
    };

    (ct, sym_ct, nonce)
}

pub(crate) fn decrypt(sk: Scalar, ct: (Ciphertext, Vec<u8>), nonce: Nonce<U12>) -> [u8; 32] {
    let p = elgamal_dec(sk, ct.0);

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, pzip(p));
    let k = hasher.finalize();

    let cipher = Aes256Gcm::new(&k);
    let pt = cipher.decrypt(&nonce, ct.1.as_ref());

    match pt {
        Ok(m) => m.try_into().unwrap(),
        Err(_) => panic!("Symmetric decryption failed")
    }
}

// Use the baby-step giant-step algorithm to compute the discrete log between
// two values (when the discrete log is small). This is only ever used to unmask a
// number of loyalty points which, by construction of our scheme, is always
// positive, so we limit our search space to (0, max points).
pub(crate) fn dlog_base_g(gx: Point) -> i32 {
    let m = (MAX_POINTS as f32).sqrt() as i32 + 1;

    let mut res: Option<i32> = None;
    let gm_inv = &int_to_scalar(-1*m)*G;
    let mut gamma = gx.clone();
    for i in 0..m {
        let k = pzip(gamma);
        if DLOG_TABLE.contains_key(&k) {
            res = Some(i*m + DLOG_TABLE[&k]);
            break;
        }
        gamma = gamma + gm_inv;
    }

    match res {
        Some(x) => x,
        None => panic!("Number of points out of bounds")
    }
}

/* // Brute force DL decryption
// The result of ElGamal decryption (mg) is the value m*g. Assuming m is a small scalar,
// we can extract it by guessing and checking different values until we find an m
// such that mg = m*g.
pub(crate) fn dlog_brute_force(g: Point, gx: Point) -> i32 {
    let mut m: u32 = 0;
    loop {
        if &Scalar::from(m) * g == gx {
            break m as i32;
        } else if &(Scalar::zero() - Scalar::from(m)) * G == gx {
            break -1 * (m as i32);
        } else if m > MAX_POINTS {
            panic!("Looping too long");
        } {
            m += 1;
        }
    }
} */

pub(crate) fn int_to_scalar(m: i32) -> Scalar {
    let m_pos: u32 = m.abs() as u32;
    let m_scalar = if m == m_pos as i32 { Scalar::from(m_pos) }
                   else { Scalar::zero() - Scalar::from(m_pos) };
    m_scalar
}

#[derive(Clone)]
pub(crate) struct TxAndProof {
    pub r2: Point,     // Second element of a receipt: h^m
    pub r3: Point,     // Third element of a receipt: g^mx
    v: Point,      // Auxilliary variables for nonlinear proof
    e: Point,
    vx: Point,
    ex: Point,

    r2_t: Point,
    r3_t: Point,
    v_t: Point,
    e_t: Point,
    vx_t: Point,
    ex_t: Point,

    m_z: Scalar,
    a_z: Scalar,
    y_z: Scalar,
    t_z: Scalar
}

pub(crate) fn zk_tx_prove(masked_m: Point, masked_x: Point, m: Scalar, x: Scalar) -> TxAndProof {
    let r2 = masked_m;
    let r3 = masked_x;
    let a = m*x;
    let u = u_point();
    
    // Setup temporary variables for nonlinear proof.
    // Need to share: v, e, vx, ex
    let y = Scalar::random(&mut OsRng);
    let t = Scalar::random(&mut OsRng);
    let v  = &y*G;
    let e  = &y*u + &m*G;
    let vx = &t*G;
    let ex = &t*u + &a*G;

    // Commitment
    let m_t = Scalar::random(&mut OsRng);
    let a_t = Scalar::random(&mut OsRng);
    let y_t = Scalar::random(&mut OsRng);
    let t_t = Scalar::random(&mut OsRng);

    let r2_t = &m_t*h_point();
    let r3_t = &a_t*G;
    let v_t = &y_t*G;
    let e_t = &y_t*u + &m_t*G;
    let vx_t = &t_t*G;
    let ex_t = &t_t*u + &a_t*G;

    // Challenge
    let mut hasher = Sha512::default();
    for elt in [r2, r3, v, e, vx, ex, r2_t, r3_t, v_t, e_t, vx_t, ex_t].iter() {
        let elt_bytes = pzip(*elt);
        Update::update(&mut hasher, &elt_bytes);
    }
    
    let c = Scalar::from_hash(hasher);

    // Response
    let m_z = m_t + m*c;
    let a_z = a_t + a*c;
    let y_z = y_t + y*c;
    let t_z = t_t + t*c;

    TxAndProof {
        r2: r2,
        r3: r3,
        v: v,
        e: e,
        vx: vx,
        ex: ex,
    
        r2_t: r2_t,
        r3_t: r3_t,
        v_t: v_t,
        e_t: e_t,
        vx_t: vx_t,
        ex_t: ex_t,
    
        m_z: m_z,
        a_z: a_z,
        y_z: y_z,
        t_z: t_z
    }
}

pub(crate) fn zk_tx_verify(pi: &TxAndProof) -> bool {
    let u = u_point();

    // Recompute c
    let mut hasher = Sha512::default();
    for elt in [pi.r2, pi.r3, pi.v, pi.e, pi.vx, pi.ex,
                pi.r2_t, pi.r3_t, pi.v_t, pi.e_t, pi.vx_t, pi.ex_t].iter() {
        let elt_bytes = pzip(*elt);
        Update::update(&mut hasher, &elt_bytes);
    }
    let c = Scalar::from_hash(hasher);

    let check1 = &pi.m_z * h_point() == pi.r2_t + &c * pi.r2;
    let check2 = &pi.a_z * G == pi.r3_t + &c * pi.r3;
    let check3 = &pi.y_z * G == pi.v_t + &c * pi.v;
    let check4 = &pi.y_z * u + &pi.m_z * G == pi.e_t + &c * pi.e;
    let check5 = &pi.t_z * G == pi.vx_t + &c * pi.vx;
    let check6 = &pi.t_z * u + &pi.a_z * G == pi.ex_t + &c * pi.ex;

    check1 && check2 && check3 && check4 && check5 && check6
}

#[derive(Clone)]
pub(crate) struct SettleProof {
    vs: Vec::<Point>,
    es: Vec::<Point>,
    vxs: Vec::<Point>,
    exs: Vec::<Point>,
    
    b1_t: Point,
    b2_t: Point,
    b_mts: Vec::<Point>,
    v_ts: Vec::<Point>,
    e_ts: Vec::<Point>,
    vx_ts: Vec::<Point>,
    ex_ts: Vec::<Point>,

    m_zs: Vec::<Scalar>,
    x_zs: Vec::<Scalar>,
    a_zs: Vec::<Scalar>,
    y_zs: Vec::<Scalar>,
    t_zs: Vec::<Scalar>
}

// Input: a public balance x, the server's balance bal, and lists of values (h^m, x, m)
// for each transaction touching this balance.
// Output: four auxilliary variables for each transaction, and the commitment/response
// components of the corresponding ZK proof.
pub(crate) fn zk_settle_prove(x: i32, bal: Point, b_ms: &Vec::<Point>,
                              xs: &Vec::<Scalar>, ms: &Vec::<Scalar>) -> SettleProof {
    // Decompress
    let n = xs.len();                        // Number of transactions
    let b1 = &int_to_scalar(x) * G;          // Algebraic balance representation
    let b2 = bal;                            // Masked balance
    let h = h_point();
    let u = u_point();

    // Auxilliary scalars for nonlinear proofs
    let mut aas = Vec::<Scalar>::with_capacity(n);  // 'as' is a Rust keyword
    let mut ys = Vec::<Scalar>::with_capacity(n);
    let mut ts = Vec::<Scalar>::with_capacity(n);
    // Auxilliary group elements for nonlinear proofs
    let mut vs = Vec::<Point>::with_capacity(n);
    let mut es = Vec::<Point>::with_capacity(n);
    let mut vxs = Vec::<Point>::with_capacity(n);
    let mut exs = Vec::<Point>::with_capacity(n);

    // Commitment
    let mut m_ts = Vec::<Scalar>::with_capacity(n);
    let mut x_ts = Vec::<Scalar>::with_capacity(n);
    let mut a_ts = Vec::<Scalar>::with_capacity(n);
    let mut y_ts = Vec::<Scalar>::with_capacity(n);
    let mut t_ts = Vec::<Scalar>::with_capacity(n);

    let mut b_mts = Vec::<Point>::with_capacity(n);
    let mut v_ts = Vec::<Point>::with_capacity(n);
    let mut e_ts = Vec::<Point>::with_capacity(n);
    let mut vx_ts = Vec::<Point>::with_capacity(n);
    let mut ex_ts = Vec::<Point>::with_capacity(n);
    for i in 0..n {
        aas.push(xs[i]*ms[i]);
        let y = Scalar::random(&mut OsRng);
        ys.push(y);
        ts.push(xs[i]*ys[i]);

        let v = &y * G;
        let e = &y * u + &ms[i] * G;
        vs.push(v);
        es.push(e);
        vxs.push(v*xs[i]);
        exs.push(e*xs[i]);

        m_ts.push(Scalar::random(&mut OsRng));
        x_ts.push(Scalar::random(&mut OsRng));
        a_ts.push(Scalar::random(&mut OsRng));
        y_ts.push(Scalar::random(&mut OsRng));
        t_ts.push(Scalar::random(&mut OsRng));

        b_mts.push(&m_ts[i]*h);
        v_ts.push(&y_ts[i]*G);
        e_ts.push(&y_ts[i]*u + (&m_ts[i]*G));
        vx_ts.push(&t_ts[i]*G);
        ex_ts.push(&t_ts[i]*u + (&a_ts[i]*G));
    }

    // TODO: can't do this as just one sum, need to multiply each x_i term individually (and change the verification as well)
    let mut at_sum = Scalar::zero();
    let mut xt_sum = Scalar::zero();
    for i in 0..n {
        at_sum = at_sum + a_ts[i];
        xt_sum = xt_sum + x_ts[i];
    }

    let b1_t = &xt_sum * G;
    let b2_t = &at_sum * G;

    // Challenge
    let mut hasher = Sha512::default();

    Update::update(&mut hasher, &pzip(b1));
    Update::update(&mut hasher, &pzip(b2));
    for i in 0..n {
        for elt in [b_ms[i], v_ts[i], e_ts[i], vx_ts[i], ex_ts[i]].iter() {
            let elt_bytes: [u8; 32] = pzip(*elt);
            Update::update(&mut hasher, &elt_bytes);
        }
    }
    
    let c = Scalar::from_hash(hasher);

    // Response
    let mut m_zs = Vec::<Scalar>::with_capacity(n);
    let mut x_zs = Vec::<Scalar>::with_capacity(n);
    let mut a_zs = Vec::<Scalar>::with_capacity(n);
    let mut y_zs = Vec::<Scalar>::with_capacity(n);
    let mut t_zs = Vec::<Scalar>::with_capacity(n);
    for i in 0..n {
        m_zs.push(m_ts[i] + ms[i]*c);
        x_zs.push(x_ts[i] + xs[i]*c);
        a_zs.push(a_ts[i] + aas[i]*c);
        y_zs.push(y_ts[i] + ys[i]*c);
        t_zs.push(t_ts[i] + ts[i]*c);
    }

    let mut a_sum = Scalar::zero();
    let mut az_sum = Scalar::zero();
    for i in 0..n {
        a_sum = a_sum + aas[i];
        az_sum = az_sum + a_zs[i];
    }

    SettleProof {
        vs: vs,
        es: es,
        vxs: vxs,
        exs: exs,
        
        b1_t: b1_t,
        b2_t: b2_t,
        b_mts: b_mts,
        v_ts: v_ts,
        e_ts: e_ts,
        vx_ts: vx_ts,
        ex_ts: ex_ts,

        m_zs: m_zs,
        x_zs: x_zs,
        a_zs: a_zs,
        y_zs: y_zs,
        t_zs: t_zs
    }
}

pub(crate) fn zk_settle_verify(x: i32, bal: Point, b_ms: Vec<Point>, pi: SettleProof) -> bool {
    let n = b_ms.len();
    let b1 = &int_to_scalar(x)*G;
    let b2 = bal;
    let u = u_point();

    // Recompute c
    let mut hasher = Sha512::default();

    Update::update(&mut hasher, &pzip(b1));
    Update::update(&mut hasher, &pzip(b2));
    for i in 0..n {
        for elt in [b_ms[i], pi.v_ts[i], pi.e_ts[i], pi.vx_ts[i], pi.ex_ts[i]].iter() {
            let elt_bytes: [u8; 32] = pzip(*elt);
            Update::update(&mut hasher, &elt_bytes);
        }
    }
    
    let c = Scalar::from_hash(hasher);

    let mut az_sum = Scalar::zero();
    let mut xz_sum = Scalar::zero();
    for i in 0..n {
        az_sum = az_sum + pi.a_zs[i];
        xz_sum = xz_sum + pi.x_zs[i];
    }

    let check_b1 = &xz_sum * G == pi.b1_t + (&c * b1);
    let check_b2 = &az_sum * G == pi.b2_t + (&c * b2);

    let mut result = check_b1 && check_b2;
    for i in 0..n {
        let b_m = b_ms[i];
        let v = pi.vs[i];
        let e = pi.es[i];
        let vx = pi.vxs[i];
        let ex = pi.exs[i];

        let b_mt = pi.b_mts[i];
        let v_t = pi.v_ts[i];
        let e_t = pi.e_ts[i];
        let vx_t = pi.vx_ts[i];
        let ex_t = pi.ex_ts[i];

        let m_z = pi.m_zs[i];
        let a_z = pi.a_zs[i];
        let y_z = pi.y_zs[i];
        let t_z = pi.t_zs[i];

        let check1 = &m_z*h_point() == b_mt + (&c*b_m);
        let check2 = &y_z*G == v_t + (&c*v);
        let check3 = &y_z*u + &m_z*G == e_t + (&c*e);
        let check4 = &t_z*G == vx_t + (&c*vx);
        let check5 = &t_z*u + &a_z*G == ex_t + (&c*ex);

        result = result && check1 && check2 && check3 && check4 && check5;
        if !result {
            break
        }
    }
    result
}

pub(crate) fn signature_keygen() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut rngs::OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

pub(crate) fn sign(sk: &SigningKey, p: &Point) -> Signature {
    (*sk).sign(&pzip(*p))
}

pub(crate) fn verify(vk: VerifyingKey, p: &Point, s: Signature) -> bool {
    vk.verify(&pzip(*p), &s).is_ok()
}