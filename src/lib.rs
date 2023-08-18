mod crypto;
use rs_merkle::{MerkleTree, algorithms::Sha256};
use std::collections::HashMap;
use std::vec::Vec;

struct Server {
    num_users: u32,
    users: Vec<UserRecord>,
    merkle_tree: MerkleTree<Sha256>,
    tmp: HashMap<u8, ServerTxTmp>, // TODO: indexed by client commitments, fix key type
}

struct ServerTxTmp {
    i_s: u32, // Server's chosen index for card-swapping phase
    uid_b: u32 // Barcode owner's user ID
}

struct UserRecord {
    barcode: u64,
    uid: u32,
    balance: [u8; 32],
    pk_enc: [u8; 32]
}

impl Server {
    pub fn new() -> Self {
        mut Server {
            num_users: 0,
            users: Vec::new();
            merkle_tree: MerkleTree::<Sha256>::new();
            tmp: HashMap::new();
        }
    }

    fn register_user(&self, barcode: u32, pk_enc: Option<[u8; 32]>) {
        let init_balance = &crypto::elgamal_enc(pk_enc, 0)[0..2];
        let user_rec = UserRecord {barcode, self.num_users, init_balance, pk_enc};
        self.users.push(user_rec);
        // TODO: add merkle
        self.num_users += 1;
    }

    fn share_state() -> (&self, u32, bool) {
        return (self.num_users, self.handle_points); // TODO: add merkle
    }

    // fn process_tx_hello_response

    // fn process_tx_barcode_gen

    // fn process_tx

    // fn settle_balance_hello

    // fn settle_balance_finalize
}

struct Client {
    handle_points: bool,
    barcode: u32,
    num_users: u32,
    merkle_root: Some<bool>,
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