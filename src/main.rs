mod lib;
use lib::*;
use std::vec::Vec;
use rand::Rng;
use std::time::{Instant, Duration};
use rs_merkle::{MerkleTree, algorithms, Hasher, MerkleProof};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

const N_CLIENTS: usize = 1000;

fn main() {
    let mut server = Server::new();
    
    let mut clients = Vec::<Client>::with_capacity(N_CLIENTS);

    println!("---------------------------");
    println!("--- Client Registration ---");
    println!("---------------------------");

    let now = Instant::now();
    for i in 0..N_CLIENTS {
        let barcode: u64 = rand::random();
        let c = Client::new(barcode);

        clients.push(c);
    }
    let time_client = now.elapsed();

    let now = Instant::now();
    for i in 0..N_CLIENTS {
        let client_data = clients[i].register_with_server();
        let barcode = client_data.0;
        let pk = client_data.1;

        server.register_user(barcode, pk);
    }
    let time_server = now.elapsed();

    println!("Client: {:.2?}, Server: {:.2?}", time_client, time_server);

    println!("------------------------------");
    println!("--- Transaction Processing ---");
    println!("------------------------------");

    struct Tx {
        uid_s: u32,
        points: i32,
        com: Option<Com>,
        i_s: Option<u32>,
        i_c: Option<u32>,
        r: Option<[u8; 32]>,
        uid_b: Option<u32>,
        barcode: Option<u64>,
        pk_b: Option<Point>,
        pi_merkle: Option<MerkleProof<algorithms::Sha256>>,
        m_ct: Option<Ciphertext>,
        pi_tx: Option<TxAndProof>,
        sigma: Option<Signature>
    }

    let n_txs = 500;
    let min_users = 1000;
    let max_users = 10000;
    let step = min_users;

    let mut time_client = Duration::ZERO;
    let mut time_server = Duration::ZERO;

    let mut server = Server::new();
    let mut clients = Vec::<Client>::with_capacity(max_users);

    // let now = Instant::now();
    // Initialize a system with a certain number of users,
    // and time how long it takes to process <n_txs> transactions
    for n_users in (min_users..(max_users+1)).step_by(step) {
        println!("{}", n_users);

        // Initialise another <step> clients and register with server
        for i in 0..step {
            let barcode: u64 = rand::random();
            let mut c = Client::new(barcode);
            clients.push(c);

            let client_data = clients.last_mut().unwrap().register_with_server();
            server.register_user(client_data.0, client_data.1);
        }

        // Inform every user of the new merkle root
        let server_data = server.share_state();
        for i in 0..n_users {
            clients[i].update_state(i.try_into().unwrap(), server_data.0, server_data.1);
        }

        // Process transactions
        let mut txs = Vec::<Tx>::with_capacity(n_txs);
        for i in 0..n_txs {
            let shopper_uid: u32 = rand::thread_rng().gen_range(0..n_users).try_into().unwrap();
            let points_used: i32 = rand::thread_rng().gen_range(0..300).try_into().unwrap();
            txs.push(Tx {
                uid_s: shopper_uid,
                points: points_used,
                com: None,
                i_s: None,
                i_c: None,
                r: None,
                uid_b: None,
                barcode: None,
                pk_b: None,
                pi_merkle: None,
                m_ct: None,
                pi_tx: None,
                sigma: None
            });
        }

        // -----------------------------
        let now = Instant::now();
        for mut tx in &mut txs {
            let shopper: &mut Client = &mut clients[tx.uid_s as usize];
            let com = shopper.process_tx_hello();
            tx.com = Some(com);
        }
        time_client += now.elapsed();
        // -----------------------------

        // -----------------------------
        let now = Instant::now();
        for mut tx in &mut txs {
            let i_s = server.process_tx_hello_response(tx.com.unwrap(), tx.uid_s);
            tx.i_s = Some(i_s);
        }
        time_server += now.elapsed();
        // -----------------------------

        // -----------------------------
        let now = Instant::now();
        for mut tx in &mut txs {
            let i_s = tx.i_s.unwrap();
            let com = tx.com.unwrap();
            let mut shopper = &mut clients[tx.uid_s as usize];
            let i_c_r = shopper.process_tx_compute_id(i_s, com);
            tx.i_c = Some(i_c_r.0);
            tx.r = Some(i_c_r.1);
        }
        time_client += now.elapsed();
        // -----------------------------

        // -----------------------------
        let now = Instant::now();
        for mut tx in &mut txs {
            let i_c = tx.i_c.unwrap();
            let r = tx.r.unwrap();
            let com = tx.com.unwrap();

            let out = server.process_tx_barcode_gen(i_c, r, com);
            tx.uid_b = Some(out.0);
            tx.barcode = Some(out.1);
            tx.pk_b = Some(out.2);
            tx.pi_merkle = Some(out.3);
        }
        time_server += now.elapsed();
        // -----------------------------

        // -----------------------------
        let now = Instant::now();
        for mut tx in &mut txs {
            let shopper: &mut Client = &mut clients[tx.uid_s as usize];
            
            let pi_merkle = tx.pi_merkle.as_ref().unwrap();
            let barcode = tx.barcode.unwrap();
            let pk_b = tx.pk_b.unwrap();
            let com = tx.com.unwrap();
            let points = tx.points;

            let out = shopper.process_tx(pi_merkle, barcode, points, pk_b, com);
            tx.m_ct = Some(out.0);
            tx.pi_tx = Some(out.1);
        }
        time_client += now.elapsed();
        // -----------------------------

        // -----------------------------
        let now = Instant::now();
        for mut tx in &mut txs {
            let m_ct = tx.m_ct.clone().unwrap();
            let pi_tx = tx.pi_tx.clone().unwrap();
            let com = tx.com.unwrap();

            let sigma = server.process_tx(m_ct, pi_tx, com);
            tx.sigma = Some(sigma);
        }
        time_server += now.elapsed();
        // -----------------------------

        // -----------------------------
        let now = Instant::now();
        for mut tx in &mut txs {
            let shopper: &mut Client = &mut clients[tx.uid_s as usize];
            let com = tx.com.unwrap();
            let sigma = tx.sigma.unwrap();

            shopper.process_tx_coda(sigma, com);
        }
        time_client += now.elapsed();
        // -----------------------------
    }
}