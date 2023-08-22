mod crypto;
use rs_merkle::{MerkleTree, algorithms, Hasher, MerkleProof};
use std::collections::HashMap;
use std::vec::Vec;
use serde_derive::Serialize;
use rand::Rng;
use sha2::{Sha256, Digest};

type Com = [u8; 32];
type Ciphertext = ([u8; 32], [u8; 32]);
type Key = [u8; 32];

struct Server {
    num_users: u32, 
    users: HashMap<u32, UserRecord>,
    merkle_tree: MerkleTree<algorithms::Sha256>,
    tmp: HashMap<Com, ServerTxTmp>,
}

struct ServerTxTmp {
    i_s: Option<u32>, // Server's chosen index for card-swapping phase
    uid_b: Option<u32> // Barcode owner's user ID
}

// The server's record of a user in the system
#[derive(Debug, Serialize, Clone)]
struct UserRecord {
    barcode: u64,
    balance: Ciphertext,
    pk_enc: Key
}

// User data stored in the server's Merkle tree
#[derive(Debug, Serialize, Clone)]
struct TreeEntry {
    uid: u32,
    barcode: u64,
    pk_enc: Key
}

impl TreeEntry {
    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl Server {
    pub fn new() -> Self {
        Server {
            num_users: 0,
            users: HashMap::new(),
            merkle_tree: MerkleTree::<algorithms::Sha256>::new(),
            tmp: HashMap::new()
        }
    }

    fn register_user(&mut self, barcode: u64, pk_enc: Key) {
        let ct = &crypto::elgamal_enc(pk_enc, 0);
        let init_balance = (ct.0, ct.1);

        let user_rec = UserRecord {
            barcode: barcode,
            balance: init_balance,
            pk_enc: pk_enc};
        let leaf = TreeEntry {
            uid: self.num_users,
            barcode: barcode,
            pk_enc: pk_enc
        };

        // Add user to list and to merkle tree
        self.users.insert(
            self.num_users,
            user_rec
        );
        self.merkle_tree.insert(algorithms::Sha256::hash(leaf.to_bytes().as_slice()));
        self.merkle_tree.commit();

        self.num_users += 1;
    }

    fn share_state(&self) -> (u32, <algorithms::Sha256 as rs_merkle::Hasher>::Hash) {
        let root = self.merkle_tree.root().unwrap();
        return (self.num_users, root);
    }

    // Step 1 of a transaction request
    
    // Input: shopper user ID, commitment to a chosed random ID
    // Output: a server-chosen random ID
    fn process_tx_hello_response(&mut self, com: Com) -> u32 {
        let i_s = rand::thread_rng().gen_range(0..self.num_users);
        let mut tmp = ServerTxTmp {
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
    fn process_tx_barcode_gen(&mut self, i_c: u32, r: [u8; 32], tx_id: Com) -> (u32, u64, Key, MerkleProof<algorithms::Sha256>) {
        let mut tmp: &mut ServerTxTmp = self.tmp.get_mut(&tx_id).unwrap();

        // Recompute commitment and check that it matches.
        let mut hasher = Sha256::new();
        hasher.update(i_c.to_le_bytes());
        hasher.update(r);
        let com_test: [u8; 32] = hasher.finalize().into();

        assert!(com_test == tx_id, "Invalid commit");

        let uid_b = (i_c + tmp.i_s.unwrap()) % self.num_users;

        tmp.uid_b = Some(uid_b);

        let user_b: &UserRecord = &self.users.get(&uid_b).unwrap();
        let barcode = user_b.barcode;
        let pk_b = user_b.pk_enc;

        let pi: MerkleProof<algorithms::Sha256> = self.merkle_tree.proof(&[uid_b.try_into().unwrap()]);

        (uid_b, barcode, pk_b, pi)
    }

    // Step 3 of a transaction request
    fn process_tx(&mut self, shopper: u32, cts: Ciphertext, ctb: Ciphertext, pi: crypto::CompressedCtEqProof, tx_id: Com) {
        let mut tmp: &mut ServerTxTmp = self.tmp.get_mut(&tx_id).unwrap();

        assert!(crypto::zk_ct_eq_verify(pi));
    }

    // fn settle_balance_hello
    fn settle_balance_hello(&self, uid: u32) -> Ciphertext {
        self.users.get(&uid).unwrap().balance
    }

    // fn settle_balance_finalize
    fn settle_balance_finalize(&self, pi: crypto::CompressedCtDecProof) -> bool {
        crypto::zk_ct_dec_verify(pi)
    }
}

struct Client {
    handle_points: bool,
    barcode: u32,
    num_users: u32,
    merkle_root: Option<bool>,
    tmp: u8 // TODO: add what tmp needs to store
}

impl Client {
    // fn new

    // fn register_with_server

    // fn update_state

    // fn process_tx_hello

    // fn process_tx_compute_id

    // fn process_tx

    // fn settle_balance
}