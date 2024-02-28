This code accompanies the paper CheckOut: User-Controlled Anonymization for Customer Loyalty Programs.

Raw data collected in our evaluation is reported in `results_client.txt` and `results_server.txt`. Client measurements were taken on a Moto G Stylus 5G phone running Android 11, and server measurements were taken on a server with an Intel Core i7-11700K processor @ 3.60 GHz running Ubuntu 20.04.6 LTS.

## Installation

This project is built in Rust. Dependencies are listed in `Cargo.toml`.

To run the benchmarks reported in the paper, navigate to the LoyaltyPointsCrypto folder, and run `cargo run --release`.

### Android

To run on Android, first install [Termux](https://termux.dev/en/), and then install Rust as follows:

````
pkg install rust
````

Then follow the instructions above. You will need to place the project file within your home directory; to do so, you may need to allow Termux permission access to your files and media.