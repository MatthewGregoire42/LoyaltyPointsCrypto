mod crypto;
// use rs_merkle::{MerkleTree, algorithms, Hasher, MerkleProof};
// use std::collections::HashMap;
// use std::vec::Vec;
// use serde_derive::Serialize;
// use rand::Rng;
// use sha2::{Sha256, Digest};
// use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
// use curve25519_dalek::RistrettoPoint;

// type Com = [u8; 32];
// type Receipt = ();

// type Point = RistrettoPoint;

// struct Server {
//     num_users: u32,
//     sk: SigningKey,
//     vk: VerifyingKey,
//     users: HashMap<u32, UserRecord>,
//     merkle_tree: MerkleTree<algorithms::Sha256>,
//     tmp: HashMap<Com, ServerTxTmp>,
// }

// struct ServerTxTmp {
//     i_s: Option<u32>, // Server's chosen index for card-swapping phase
//     uid_b: Option<u32> // Barcode owner's user ID
// }

// // The server's record of a user in the system
// #[derive(Debug, Serialize, Clone)]
// struct UserRecord {
//     barcode: u64,
//     balance: Point,
//     pk_enc: CPoint
// }

// // User data stored in the server's Merkle tree
// #[derive(Debug, Serialize, Clone)]
// struct TreeEntry {
//     uid: u32,
//     barcode: u64,
//     pk_enc: CPoint
// }

// impl TreeEntry {
//     fn to_bytes(&self) -> Vec<u8> {
//         bincode::serialize(&self).unwrap()
//     }
// }

// impl Server {
//     pub fn new() -> Self {
//         Server {
//             num_users: 0,
//             users: HashMap::new(),
//             merkle_tree: MerkleTree::<algorithms::Sha256>::new(),
//             tmp: HashMap::new()
//         }
//     }

//     fn register_user(&mut self, barcode: u64, pk_enc: CPoint) {
//         let ct = &crypto::elgamal_enc(pk_enc, 0);
//         let init_balance = (ct.0, ct.1);

//         let user_rec = UserRecord {
//             barcode: barcode,
//             balance: init_balance,
//             pk_enc: pk_enc};
//         let leaf = TreeEntry {
//             uid: self.num_users,
//             barcode: barcode,
//             pk_enc: pk_enc
//         };

//         // Add user to list and to merkle tree
//         self.users.insert(
//             self.num_users,
//             user_rec
//         );
//         self.merkle_tree.insert(algorithms::Sha256::hash(leaf.to_bytes().as_slice()));
//         self.merkle_tree.commit();

//         self.num_users += 1;
//     }

//     fn share_state(&self) -> (u32, <algorithms::Sha256 as rs_merkle::Hasher>::Hash) {
//         let root = self.merkle_tree.root().unwrap();
//         return (self.num_users, root);
//     }

//     // Step 1 of a transaction request
    
//     // Input: shopper user ID, commitment to a chosed random ID
//     // Output: a server-chosen random ID
//     fn process_tx_hello_response(&mut self, com: Com) -> u32 {
//         let i_s = rand::thread_rng().gen_range(0..self.num_users);
//         let mut tmp = ServerTxTmp {
//             i_s: Some(i_s),
//             uid_b: None
//         };

//         // Store in-progress TX info server side
//         self.tmp.insert(
//             com,
//             tmp
//         );
        
//         i_s
//     }

//     // Step 2 of a transaction request

//     // Input: shopper UID, opened commitment contents: client-chosen random ID and mask
//     // Output: barcode owner's UID, barcode, and public key, and merkle inclusion proof
//     fn process_tx_barcode_gen(&mut self, i_c: u32, r: [u8; 32], tx_id: Com) -> (u32, u64, CPoint, MerkleProof<algorithms::Sha256>) {
//         let mut tmp: &mut ServerTxTmp = self.tmp.get_mut(&tx_id).unwrap();

//         // Recompute commitment and check that it matches.
//         let mut hasher = Sha256::new();
//         hasher.update(i_c.to_le_bytes());
//         hasher.update(r);
//         let com_test: Com = hasher.finalize().into();

//         assert!(com_test == tx_id, "Invalid commit");

//         let uid_b = (i_c + tmp.i_s.unwrap()) % self.num_users;

//         tmp.uid_b = Some(uid_b);

//         let user_b: &UserRecord = &self.users.get(&uid_b).unwrap();
//         let barcode = user_b.barcode;
//         let pk_b = user_b.pk_enc;

//         let pi: MerkleProof<algorithms::Sha256> = self.merkle_tree.proof(&[uid_b.try_into().unwrap()]);

//         (uid_b, barcode, pk_b, pi)
//     }

//     // Step 3 of a transaction request
//     fn process_tx(&mut self, shopper: u32, cts: Ciphertext, ctb: Ciphertext, pi: crypto::CompressedCtEqProof, tx_id: Com) {
//         // let mut tmp: &mut ServerTxTmp = self.tmp.get_mut(&tx_id).unwrap();

//         assert!(crypto::zk_ct_eq_verify(pi));

//         self.tmp.remove(&tx_id);
//     }

//     // fn settle_balance_hello
//     fn settle_balance_hello(&self, uid: u32) -> Ciphertext {
//         self.users.get(&uid).unwrap().balance
//     }

//     // fn settle_balance_finalize
//     fn settle_balance_finalize(&self, pi: crypto::CompressedCtDecProof) -> bool {
//         crypto::zk_ct_dec_verify(pi)
//     }
// }

// struct Client {
//     barcode: u64,
//     num_users: u32,
//     merkle_root: Option<<algorithms::Sha256 as rs_merkle::Hasher>::Hash>,
//     tmp: HashMap<Com, ClientTxTmp>,
//     sk_enc: CScalar,
//     pk_enc: CPoint
// }

// struct ClientTxTmp {
//     i_c: Option<u32>,
//     r: Option<[u8; 32]>,
//     uid_b: Option<u32>,

// }

// impl Client {
//     fn new(barcode: u64) -> Self {
//         let keys = crypto::elgamal_keygen();
//         Client {
//             barcode: barcode,
//             num_users: 1,
//             merkle_root: None,
//             tmp: HashMap::new(),
//             sk_enc: keys.0,
//             pk_enc: keys.1
//         }
//     }

//     fn register_with_server(&self) -> (u64, CPoint) {
//         (self.barcode, self.pk_enc)
//     }

//     fn update_state(&mut self, num_users: u32, merkle_root: <algorithms::Sha256 as Hasher>::Hash) {
//         self.num_users = num_users;
//         self.merkle_root = Some(merkle_root);
//     }

//     // Step 1 of a transaction request

//     // Input: N/A
//     // Output: commitment to a randomly chosen user ID
//     fn process_tx_hello(&mut self) -> Com {
//         // Commit to a random index and send it to the server
//         let i_c = rand::thread_rng().gen_range(0..self.num_users);
//         let r = rand::thread_rng().gen::<[u8; 32]>();
//         let mut hasher = Sha256::new();
//         hasher.update(i_c.to_le_bytes());
//         hasher.update(r);
//         let com: Com = hasher.finalize().into();

//         let tx_id = com;
//         self.tmp.insert(
//             tx_id,
//             ClientTxTmp {
//                 i_c: Some(i_c),
//                 r: Some(r),
//                 uid_b: None,
//             }
//         );

//         com
//     }

//     // Step 2 of a transaction request

//     // Input: server's randomly chosen barcode UID
//     // Output: opened commitment to client-chosed barcode UID
//     fn process_tx_compute_id(&mut self, i_s: u32, tx_id: Com) -> (u32, [u8; 32]) {
//         let mut tmp: &mut ClientTxTmp = self.tmp.get_mut(&tx_id).unwrap();

//         let i = (tmp.i_c.unwrap() + i_s) % self.num_users;
//         tmp.uid_b = Some(i);

//         (tmp.i_c.unwrap(), tmp.r.unwrap())
//     }

//     fn verify_merkle_proof(&mut self, barcode: u64, pi: MerkleProof<algorithms::Sha256>, pkb: CPoint, tx_id: Com) -> bool {
//         let tmp: &ClientTxTmp = self.tmp.get(&tx_id).unwrap();

//         let leaf = TreeEntry {
//             uid: tmp.uid_b.unwrap(),
//             barcode: barcode,
//             pk_enc: pkb
//         };
//         let tree_contents = algorithms::Sha256::hash(leaf.to_bytes().as_slice());

//         let test = pi.verify(self.merkle_root.unwrap(), &[tmp.uid_b.unwrap().try_into().unwrap()], &[tree_contents], 1);

//         assert!(test);

//         test
//     }

//     // Step 3 of a transaction request
//     fn process_tx(&mut self, pi: MerkleProof<algorithms::Sha256>, barcode: u64, points: i32, pkb: CPoint, tx_id: Com) -> (Ciphertext, Ciphertext, crypto::CompressedCtEqProof) {
//         // Verify Merkle proof that the agreed upon index is in the tree
//         self.verify_merkle_proof(barcode, pi, pkb, tx_id);

//         // Encrypt the number of points under both public keys
//         let cts = crypto::elgamal_enc(self.pk_enc, -1*points);
//         let cts_data = crypto::CompressedTxCiphertextData::new(
//             (cts.0, cts.1), cts.2, -1*points, self.pk_enc
//         );

//         let ctb = crypto::elgamal_enc(pkb, points);
//         let ctb_data = crypto::CompressedTxCiphertextData::new(
//             (ctb.0, ctb.1), ctb.2, points, pkb
//         );

//         // Generate a zero knowledge proof that these encrypt the same value
//         let pi = crypto::zk_ct_eq_prove(cts_data, ctb_data);

//         self.tmp.remove(&tx_id);

//         ((cts.0, cts.1), (ctb.0, ctb.1), pi)
//     }

//     fn settle_balance(&self, ct: Ciphertext) -> (i32, crypto::CompressedCtDecProof) {
//         let plaintext = crypto::elgamal_dec(self.sk_enc, ct);
//         let pi = crypto::zk_ct_dec_prove(ct, plaintext, self.sk_enc, self.pk_enc);

//         (plaintext, pi)
//     }
// }