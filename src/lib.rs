mod crypto;
use rs_merkle::{MerkleTree, algorithms::Sha256, Hasher, MerkleProof};
use std::collections::HashMap;
use std::vec::Vec;
use serde_derive::Serialize;
use rand::Rng;

type Com = [u8; 32];
type Ciphertext = ([u8; 32], [u8; 32]);
type Key = [u8; 32];

struct Server {
    num_users: u32, 
    users: HashMap<u32, UserRecord>,
    merkle_tree: MerkleTree<Sha256>,
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
            merkle_tree: MerkleTree::<Sha256>::new(),
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
        self.merkle_tree.insert(Sha256::hash(leaf.to_bytes().as_slice()));
        self.merkle_tree.commit();

        self.num_users += 1;
    }

    fn share_state(&self) -> (u32, <Sha256 as rs_merkle::Hasher>::Hash) {
        let root = self.merkle_tree.root().unwrap();
        return (self.num_users, root);
    }

    // Step 1 of a transaction request
    
    // Input: shopper user ID, commitment to a chosed random ID
    // Output: a server-chosen random ID
    fn process_tx_hello_response(&mut self, com: Com) -> u32 {
        let i_s = rand::thread_rng().gen_range(0..self.num_users);

        // Store in-progress TX info server side
        self.tmp.insert(
            com,
            ServerTxTmp {
                i_s: Some(i_s),
                uid_b: None
            }
        );
        
        i_s
    }

    // fn process_tx_barcode_gen
    // Step 2 of a transaction request

    // Input: shopper UID, opened commitment contents: client-chosen random ID and mask
    // Output: barcode owner's UID, barcode, and public key, and merkle inclusion proof
    fn process_tx_barcode_gen(&mut self, i_c: u32, r: u32, tx_id: Com) -> u32, u64, Key, MerkleProof {

    }

    // fn process_tx

    // fn settle_balance_hello

    // fn settle_balance_finalize
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