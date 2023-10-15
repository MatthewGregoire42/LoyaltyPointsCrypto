mod lib;
use lib::*;
use std::vec::Vec;
use rand::Rng;
use std::time::Instant;

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
}