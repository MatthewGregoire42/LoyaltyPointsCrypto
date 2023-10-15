mod crypto;
use crypto::{pzip, puzip, TxAndProof, h_point, SettleProof};
use rs_merkle::{MerkleTree, algorithms, Hasher, MerkleProof};
use std::collections::{HashMap, HashSet};
use std::vec::Vec;
use serde_derive::Serialize;
use rand::Rng;
use sha2::{Sha256, Digest};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use aes_gcm::{Nonce};
use generic_array::typenum::U12;

type Com = [u8; 32];
type Point = RistrettoPoint;
type CPoint = [u8; 32];
type Ciphertext = ((Point, Point), Vec<u8>, Nonce<U12>);
type Receipt = (Ciphertext, TxAndProof);

//////////////////////////////////////////////////////////////////
// Server code
//////////////////////////////////////////////////////////////////

pub(crate) struct Server {
    num_users: u32,
    sk: SigningKey,
    vk: VerifyingKey,
    users: HashMap<u32, UserRecord>,
    receipts: HashMap<u32, Vec<Receipt>>,
    merkle_tree: MerkleTree<algorithms::Sha256>,
    tmp: HashMap<Com, ServerTxTmp>,
    default_bal: CPoint
}

struct ServerTxTmp {
    uid_s: u32, // Shopper's user ID
    i_s: Option<u32>, // Server's chosen index for card-swapping phase
    uid_b: Option<u32> // Barcode owner's user ID
}

// The server's record of a user in the system
#[derive(Debug, Serialize, Clone)]
struct UserRecord {
    barcode: u64,
    balance: CPoint,
    pk_enc: CPoint
}

// User data stored in the server's Merkle tree
#[derive(Debug, Serialize, Clone)]
struct TreeEntry {
    uid: u32,
    barcode: u64,
    pk_enc: CPoint
}

impl TreeEntry {
    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl Server {
    pub(crate) fn new() -> Self {
        let keys = crypto::signature_keygen();
        Server {
            num_users: 0,
            sk: keys.0,
            vk: keys.1,
            users: HashMap::new(),
            receipts: HashMap::new(),
            merkle_tree: MerkleTree::<algorithms::Sha256>::new(),
            tmp: HashMap::new(),
            default_bal: pzip(crypto::G*&crypto::int_to_scalar(0))
        }
    }

    pub(crate) fn register_user(&mut self, barcode: u64, pk_enc: CPoint) {
        let user_rec = UserRecord {
            barcode: barcode,
            balance: self.default_bal,
            pk_enc: pk_enc};
        let leaf = TreeEntry {
            uid: self.num_users,
            barcode: barcode,
            pk_enc: pk_enc
        };

        // Add user to list and to merkle tree, and make a place to put receipts in transit
        self.users.insert(
            self.num_users,
            user_rec
        );
        self.merkle_tree.insert(algorithms::Sha256::hash(leaf.to_bytes().as_slice()));
        self.merkle_tree.commit();

        self.receipts.insert(
            self.num_users,
            Vec::new()
        );

        self.num_users += 1;
    }

    pub(crate) fn share_state(&self) -> (u32, <algorithms::Sha256 as rs_merkle::Hasher>::Hash, VerifyingKey) {
        let root = self.merkle_tree.root().unwrap();
        return (self.num_users, root, self.vk);
    }

    // Step 1 of a transaction request
    
    // Input: shopper user ID, commitment to a chosed random ID
    // Output: a server-chosen random ID
    pub(crate) fn process_tx_hello_response(&mut self, com: Com, uid_s: u32) -> u32 {
        let i_s = rand::thread_rng().gen_range(0..self.num_users);
        let tmp = ServerTxTmp {
            uid_s: uid_s,
            i_s: Some(i_s),
            uid_b: None
        };

        // Store in-progress TX info server side
        self.tmp.insert(
            com,
            tmp
        );
        
        i_s
    }

    // Step 2 of a transaction request

    // Input: shopper UID, opened commitment contents: client-chosen random ID and mask
    // Output: barcode owner's UID, barcode, and public key, and merkle inclusion proof
    pub(crate) fn process_tx_barcode_gen(&mut self, i_c: u32, r: [u8; 32], tx_id: Com) -> (u32, u64, Point, MerkleProof<algorithms::Sha256>) {
        let tmp: &mut ServerTxTmp = self.tmp.get_mut(&tx_id).unwrap();

        // Recompute commitment and check that it matches.
        let mut hasher = Sha256::new();
        hasher.update(i_c.to_le_bytes());
        hasher.update(r);
        let com_test: Com = hasher.finalize().into();

        assert!(com_test == tx_id, "Invalid commit");

        let uid_b = (i_c + tmp.i_s.unwrap()) % self.num_users;

        tmp.uid_b = Some(uid_b);

        let user_b: &UserRecord = &self.users.get(&uid_b).unwrap();
        let barcode = user_b.barcode;
        let pk_b = user_b.pk_enc;

        let pi: MerkleProof<algorithms::Sha256> = self.merkle_tree.proof(&[uid_b.try_into().unwrap()]);

        (uid_b, barcode, puzip(pk_b), pi)
    }

    // Step 3 of a transaction request

    // Input: tx_id, encrypted m, masked m (h^m) masked points (g^mx), and ZK correctness proof
    // Output: a signature on h^m
    pub(crate) fn process_tx(&mut self, ct: Ciphertext, tx: TxAndProof, tx_id: Com) -> Signature {
        
        assert!(crypto::zk_tx_verify(&tx), "Transaction proof failed");

        let tmp: &ServerTxTmp = self.tmp.get(&tx_id).unwrap();
        let uid_s = tmp.uid_s;
        let uid_b = tmp.uid_b.unwrap();
        
        let hm = tx.r2.clone();
        let gmx = tx.r3.clone();

        // Update both users' balances
        let bal_s = puzip(self.users[&uid_s].balance);
        let bal_b = puzip(self.users[&uid_b].balance);
        self.users.get_mut(&uid_s).unwrap().balance = pzip(bal_s + gmx);
        self.users.get_mut(&uid_b).unwrap().balance = pzip(bal_b + gmx*&crypto::int_to_scalar(-1));
        
        // Store the receipt to send to the barcode owner
        let rct  = (ct, tx);
        let rcts = self.receipts.get_mut(&uid_b).unwrap();
        rcts.push(rct);

        // Sign and return h^m
        crypto::sign(&self.sk, &hm)
    }

    // Receipt distribution
    pub(crate) fn send_receipts(&mut self, uid: u32) -> Vec<(Receipt, Signature)> {
        let mut out = Vec::new();

        let rcts = self.receipts.get_mut(&uid).unwrap();

        // Unpack h^m, and sign (h^m)^-1 = h^-m
        for rct in &*rcts {
            let hm = rct.1.r2.clone();
            let hm_inv = hm*(&crypto::int_to_scalar(-1));
            let sigma = crypto::sign(&self.sk, &hm_inv);

            out.push((rct.clone(), sigma));
        }

        rcts.remove(uid.try_into().unwrap());
        out
    }

    // Accept or reject a client's request to settle
    pub(crate) fn settle_balance(&self, uid: u32, x: i32, hms: Vec<Point>, sigmas: Vec<Signature>, pi: SettleProof) -> bool {
        let server_bal = crypto::puzip(self.users[&uid].balance);

        let gx = crypto::G*(&crypto::int_to_scalar(x));

        for i in 0..sigmas.len() {
            let hm = &hms[i];
            let s = sigmas[i];

            if !crypto::verify(self.vk, hm, s) {
                return false;
            }
        }

        crypto::zk_settle_verify(x, server_bal, hms, pi)
    }
}

//////////////////////////////////////////////////////////////////
// Client code
//////////////////////////////////////////////////////////////////

type ClientReceipt = (Scalar, Scalar, Point, Signature); // m, h^m, sigma_(h^m) stored until settling time

pub(crate) struct Client {
    pub barcode: u64,
    uid: u32,
    num_users: u32,
    merkle_root: Option<<algorithms::Sha256 as rs_merkle::Hasher>::Hash>,
    // server_vk: VerifyingKey,
    bal: i32,
    server_bal: Point,
    receipts: Vec<ClientReceipt>,
    seen_ms: HashSet<[u8; 32]>,
    tmp: HashMap<Com, ClientTxTmp>,
    sk_enc: Scalar,
    pk_enc: Point
}

struct ClientTxTmp {
    i_c: Option<u32>,
    r: Option<[u8; 32]>,
    uid_b: Option<u32>,
    m: Option<Scalar>,
    hm: Option<Point>,
    x: Option<Scalar>
}

impl Client {
    pub(crate) fn new(barcode: u64) -> Self {
        let keys = crypto::elgamal_keygen();
        Client {
            barcode: barcode,
            uid: 1,
            num_users: 1,
            merkle_root: None,
            bal: 0,
            server_bal: crypto::G*&crypto::int_to_scalar(0),
            receipts: Vec::new(),
            seen_ms: HashSet::new(),
            tmp: HashMap::new(),
            sk_enc: keys.0,
            pk_enc: keys.1
        }
    }

    pub(crate) fn register_with_server(&self) -> (u64, [u8; 32]) {
        (self.barcode, crypto::pzip(self.pk_enc))
    }

    pub(crate) fn update_state(&mut self, uid: u32, num_users: u32, merkle_root: <algorithms::Sha256 as Hasher>::Hash) {
        self.uid = uid;
        self.num_users = num_users;
        self.merkle_root = Some(merkle_root);
    }

    // Step 1 of a transaction request

    // Input: N/A
    // Output: commitment to a randomly chosen user ID
    pub(crate) fn process_tx_hello(&mut self) -> Com {
        // Commit to a random index and send it to the server
        let i_c = rand::thread_rng().gen_range(0..self.num_users);
        let r = rand::thread_rng().gen::<[u8; 32]>();
        let mut hasher = Sha256::new();
        hasher.update(i_c.to_le_bytes());
        hasher.update(r);
        let com: Com = hasher.finalize().into();

        let tx_id = com;
        self.tmp.insert(
            tx_id,
            ClientTxTmp {
                i_c: Some(i_c),
                r: Some(r),
                uid_b: None,
                m: None,
                hm: None,
                x: None
            }
        );

        com
    }

    // Step 2 of a transaction request

    // Input: server's randomly chosen barcode UID
    // Output: opened commitment to client-chosed barcode UID
    pub(crate) fn process_tx_compute_id(&mut self, i_s: u32, tx_id: Com) -> (u32, [u8; 32]) {
        let tmp: &mut ClientTxTmp = self.tmp.get_mut(&tx_id).unwrap();

        let i = (tmp.i_c.unwrap() + i_s) % self.num_users;
        tmp.uid_b = Some(i);

        (tmp.i_c.unwrap(), tmp.r.unwrap())
    }

    pub(crate) fn verify_merkle_proof(&mut self, barcode: u64, pi: MerkleProof<algorithms::Sha256>, pkb: Point, tx_id: Com) -> bool {
        let tmp: &ClientTxTmp = self.tmp.get(&tx_id).unwrap();

        let leaf = TreeEntry {
            uid: tmp.uid_b.unwrap(),
            barcode: barcode,
            pk_enc: pzip(pkb)
        };
        let tree_contents = algorithms::Sha256::hash(leaf.to_bytes().as_slice());

        let test = pi.verify(self.merkle_root.unwrap(), &[tmp.uid_b.unwrap().try_into().unwrap()], &[tree_contents], 1);

        assert!(test);

        test
    }

    // Step 3 of a transaction request
    pub(crate) fn process_tx(&mut self, pi: MerkleProof<algorithms::Sha256>, barcode: u64, points: i32, pkb: Point, tx_id: Com) -> (Ciphertext, TxAndProof) {
        // Verify Merkle proof that the agreed upon index is in the tree
        self.verify_merkle_proof(barcode, pi, pkb, tx_id);

        // Choose a random mask to encrypt
        let m_bits = rand::thread_rng().gen::<[u8; 32]>();
        let m_ct = crypto::encrypt(pkb, m_bits);

        // Convert mask to scalar and compute h^m and g^mx
        let m = Scalar::from_bytes_mod_order(m_bits);
        let x = crypto::int_to_scalar(points);
        let hm = h_point()*&m;
        let gmx = crypto::G*&(m * x);

        // Prove that (h^m, g^mx) is well-formed
        let pi = crypto::zk_tx_prove(hm, gmx, m, x);

        // Store m, h^m to associate with the signature from the server
        let tmp: &mut ClientTxTmp = self.tmp.get_mut(&tx_id).unwrap();
        tmp.m = Some(m);
        tmp.hm = Some(hm);
        tmp.x = Some(x);

        (m_ct, pi)
    }

    pub(crate) fn process_tx_coda(&mut self, sigma: Signature, tx_id: Com) {
        let tmp: &ClientTxTmp = self.tmp.get(&tx_id).unwrap();
        let m = tmp.m.unwrap();
        let hm = tmp.hm.unwrap();
        let x = tmp.x.unwrap();

        self.receipts.push((x, m, hm, sigma));

        self.tmp.remove(&tx_id);
    }

    // Receipt = (Ciphertext, TxAndProof)
    // Ciphertext = ((Point, Point), Vec<u8>, Nonce<U12>)
    pub(crate) fn process_receipts(&mut self, rcts: Vec<(Receipt, Signature)>) {
        for rct in rcts {
            let ct = rct.0.0;
            let tx_and_proof = rct.0.1;
            let hm = tx_and_proof.r2;
            let gmx = tx_and_proof.r3;

            let pk_ct = ct.0;
            let sym_ct = ct.1;
            let nonce = ct.2;

            let m_bits: [u8; 32] = crypto::decrypt(self.sk_enc, (pk_ct, sym_ct), nonce);
            let m = Scalar::from_bytes_mod_order(m_bits);

            if self.seen_ms.contains(&m_bits) {
                panic!("Invalid m");
            }
            self.seen_ms.insert(m_bits);

            assert!(crypto::zk_tx_verify(&tx_and_proof));

            let x = crypto::dlog(crypto::G * &m, gmx);

            self.bal -= x;
            self.server_bal = self.server_bal + (gmx * crypto::int_to_scalar(-1));
            self.receipts.push((crypto::int_to_scalar(x), m, hm, rct.1));
        }
    }

    /* The client settles by providing:
       - their balance (x)
       - a list of all masked m values, h^(m_i)
       - a list of all signatures on the above values
       - a proof that the information is related correctly

       The client then can reset their state.
    */
    pub(crate) fn settle_balance(&self) -> (i32, Vec<Point>, Vec<Signature>, SettleProof) {

        let x = self.bal;
        let server_bal = self.server_bal;
        let rcts = &self.receipts;

        let mut xs = Vec::new();
        let mut ms = Vec::new();
        let mut hms = Vec::new();
        let mut signatures = Vec::new();

        for rct in rcts {
            let x = rct.0;
            let m = rct.1;
            let hm = rct.2;
            let sigma = rct.3;

            xs.push(x);
            ms.push(m);
            hms.push(hm);
            signatures.push(sigma);
        }

        let pi = crypto::zk_settle_prove(x, server_bal, &hms, &xs, &ms);

        (x, hms, signatures, pi)
    }
}