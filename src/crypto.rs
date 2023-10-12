use rand_core::OsRng;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;
use curve25519_dalek::digest::Update;

const G: &RistrettoBasepointTable = &constants::RISTRETTO_BASEPOINT_TABLE;
const H: &RistrettoBasepointTable = &RistrettoBasepointTable::create(&RistrettoPoint::random(&mut OsRng));
const U: &RistrettoBasepointTable = &RistrettoBasepointTable::create(&RistrettoPoint::random(&mut OsRng));

type Point = RistrettoPoint;
type Ciphertext = (Point, Point);

fn pzip(p: Point) -> [u8; 32] {
    p.compress()
}

fn szip(s: Scalar) -> [u8; 32] {
    p.to_bytes()
}

pub(crate) fn elgamal_keygen() -> (Scalar, Point) {
    let x: Scalar = Scalar::random(&mut OsRng);
    let h: Point = &x * G;
    (x, h)
}

// Takes as parameters:
//      pk: a Point
//      m:  a message to encrypt (random mask chosen by client)
pub(crate) fn elgamal_enc(pk: Point, m: i32) -> (Point, Point, Scalar) {
    let r: Scalar = Scalar::random(&mut OsRng);

    // We need to convert m to a scalar
    let m_pos: u32 = m.abs() as u32;
    let m_scalar = if m == m_pos as i32 { Scalar::from(m_pos) }
                   else { Scalar::zero() - Scalar::from(m_pos) };

    let c1 = &r*G;
    let c2 = &m_scalar*G + r*pk;

    // y is a secret; it needs to be kept by the client to generate a proof
    // and then is discarded afterwards.
    (c1, c2, r)
}

// Takes as parameters:
//      sk: a compressed Scalar
//      ct:  a compressed (Point, Point) ciphertext
// Returns the decrypted chosen mask
pub(crate) fn elgamal_dec(sk: Scalar, ct: Ciphertext) -> i32 {
    let mg = ct.1 + (Scalar::zero() - sk) * ct.0;

    // The result of ElGamal decryption (mg) is the value m*g. Assuming m is a small scalar,
    // we can extract it by guessing and checking different values until we find an m
    // such that mg = m*g.
    // TODO: implement baby-step giant-step
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
}

pub(crate) fn add_ciphertexts(ct0: Ciphertext, ct1: Ciphertext) -> Ciphertext {
    let ct0 = (puzip(ct0.0), puzip(ct0.1));
    let ct1 = (puzip(ct1.0), puzip(ct1.1));

    ((ct0.0 + ct1.0), (ct0.1 + ct1.1))
}

pub(crate) struct TxCiphertextData {
    ciphertext: (Point, Point),
    y: Scalar,
    m: Scalar,
    public_h: Point
}

impl TxCiphertextData {
    pub(crate) fn new(ct: Ciphertext, y: Scalar, m: i32, h: Point) -> Self {
        TxCiphertextData {
            ciphertext: ct,
            y: y,
            m: int_to_scalar(m),
            public_h: h,
        }
    }
}

pub(crate) fn int_to_scalar(m: i32) -> Scalar {
    let m_pos: u32 = m.abs() as u32;
    let m_scalar = if m == m_pos as i32 { Scalar::from(m_pos) }
                   else { Scalar::zero() - Scalar::from(m_pos) };
    m_scalar
}

#[derive(Clone)]
pub(crate) struct TxAndProof {
    r2: Point,     // Second element of a receipt: h^m
    r3: Point,     // Third element of a receipt: g^mx
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
    
    // Setup temporary variables for nonlinear proof.
    // Need to share: v, e, vx, ex
    let y = Scalar::random(&mut OsRng);
    let t = Scalar::random(&mut OsRng);
    let v  = &y*G;
    let e  = &y*U + &m*G;
    let vx = &t*G;
    let ex = &t*U + &a*G;

    // Commitment
    let m_t = Scalar::random(&mut OsRng);
    let a_t = Scalar::random(&mut OsRng);
    let y_t = Scalar::random(&mut OsRng);
    let t_t = Scalar::random(&mut OsRng);

    let r2_t = &m_t*H;
    let r3_t = &a_t*G;
    let v_t = &y_t*G;
    let e_t = &y_t*U + &m_t*G;
    let vx_t = &t_t*G;
    let ex_t = &t_t*U + &a_t*G;

    // Challenge
    let mut hasher = Sha512::default();
    for elt in [r2, r3, v, e, vx, ex, r2_t, r3_t, v_t, e_t, vx_t, ex_t].iter() {
        let elt_bytes = pzip(*elt);
        hasher.update(&elt_bytes);
    }
    
    let c = Scalar::from_hash(hasher);

    // Response
    let m_z = m_t + m*c;
    let a_z = a_t + a*c;
    let y_z = y_t + y*c;
    let t_z = t_t + t*c;

    CompressedTxAndProof {
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

pub(crate) fn zk_tx_verify(pi: TxAndProof) -> bool {
    // Recompute c
    let mut hasher = Sha512::default();
    for elt in [pi.r2, pi.r3, pi.v, pi.e, pi.vx, pi.ex,
                pi.r2_t, pi.r3_t, pi.v_t, pi.e_t, pi.vx_t, pi.ex_t].iter() {
        let elt_bytes = pzip(*elt);
        hasher.update(&elt_bytes);
    }
    let c = Scalar::from_hash(hasher);

    let check1 = &pi.m_z * H == pi.r2_t + &c * pi.r2;
    let check2 = &pi.a_z * G == pi.r3_t + &c * pi.r3;
    let check3 = &pi.y_z * G == pi.v_t + &c * pi.v;
    let check4 = &pi.y_z * U + &pi.m_z * G == pi.e_t + &c * pi.e;
    let check5 = &pi.t_z * G == pi.vx_t + &c * pi.vx;
    let check6 = &pi.t_z * U + &pi.a_z * G == pi.ex_t + &c * pi.ex;

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
pub(crate) fn zk_settle_prove(x: i32, bal: Point, b_ms: Vec::<Point>,
                              xs: Vec::<Scalar>, ms: Vec::<Scalar>) -> SettleProof {
    // Decompress
    let n = xs.len();                        // Number of transactions
    let b1 = &int_to_scalar(x) * G;          // Algebraic balance representation
    let b2 = bal                             // Masked balance
    let xs = Vec::<Scalar>::with_capacity(n);

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
    let b1_t = Point::random(&mut OsRng);
    let b2_t = Point::random(&mut OsRng);

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
        ys.push(Scalar::random(&mut OsRng));
        ts.push(xs[i]*ys[i]);

        vs.push(Point::random(&mut OsRng));
        es.push(Point::random(&mut OsRng));
        vxs.push(Point::random(&mut OsRng));
        exs.push(Point::random(&mut OsRng));

        m_ts.push(Scalar::random(&mut OsRng));
        x_ts.push(Scalar::random(&mut OsRng));
        a_ts.push(Scalar::random(&mut OsRng));
        y_ts.push(Scalar::random(&mut OsRng));
        t_ts.push(Scalar::random(&mut OsRng));

        b_mts.push(&m_ts[i]*H);
        v_ts.push(&y_ts[i]*G);
        e_ts.push(&y_ts[i]*U + &m_ts[i]*G);
        vx_ts.push(&t_ts[i]*G);
        ex_ts.push(&t_ts[i]*U + &a_ts[i]*G);
    }

    // Challenge
    let mut hasher = Sha512::default();

    hasher.update(&pzip(b1));
    hasher.update(&pzip(b2));
    for i in 0..n {
        for elt in [b_ms[i], v_ts[i], e_ts[i], vx_ts[i], ex_ts[i]].iter() {
            let elt_bytes: [u8; 32] = pzip(*elt);
            hasher.update(&elt_bytes);
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

    CompressedSettleProof {
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

    // Recompute c
    let mut hasher = Sha512::default();

    hasher.update(&pzip(b1));
    hasher.update(&pzip(b2));
    for i in 0..n {
        for elt in [pi.b_ms[i], pi.v_ts[i], pi.e_ts[i], pi.vx_ts[i], pi.ex_ts[i]].iter() {
            let elt_bytes: [u8; 32] = pzip(*elt);
            hasher.update(&elt_bytes);
        }
    }
    
    let c = Scalar::from_hash(hasher);

    let az_sum = Scalar::zero();
    let xz_sum = Scalar::zero();
    for i in 0..n {
        az_sum = az_sum + pi.a_zs[i];
        xz_sum = xz_sum + pi.x_zs[i];
    }

    let check_b1 = &xz_sum * G == pi.b1_t + &c * b1;
    let check_b2 = &az_sum * G == pi.b2_t + &c * b2;

    let result = check_b1 && check_b2;

    let check = true;
    for i in 0..n {
        b_m = pi.b_ms[i];
        v = pi.vs[i];
        e = pi.es[i];
        vx = pi.vxs[i];
        ex = pi.exs[i];

        b_mt = pi.b_mts[i];
        v_t = pi.v_ts[i];
        e_t = pi.e_ts[i];
        vx_t = pi.vx_ts[i];
        ex_t = pi.ex_ts[i];

        m_z = pi.m_zs[i];
        x_z = pi.x_zs[i];
        a_z = pi.a_zs[i];
        y_z = pi.y_zs[i];
        t_z = pi.t_zs[i];

        check1 = &m_z*H == b_mt + &c*b_m;
        check2 = &y_z*G == v_t + &c*v;
        check3 = &y_z*U + &m_z*G == e_t + &c*e;
        check4 = &t_z*G == vx_t + &c*vx;
        check5 = &t_z*U + &a_z*G == ex_t + &c*ex;

        result = result && check1 && check2 && check3 && check4 && check5;
        if (!result) {
            break
        }
    }
    result
}