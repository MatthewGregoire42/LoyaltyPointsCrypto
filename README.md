This code accompanies the paper CheckOut: User-Controlled Anonymization for Customer Loyalty Programs. It is an implementation of the three CheckOut systems reported in the paper, providing card-swapping only, semihonest security, and malicious security.

Raw data collected in our evaluation is reported in `results_client.txt` and `results_server.txt`. Client measurements were taken on a Moto G Stylus 5G phone running Android 11, and server measurements were taken on a server with an Intel Core i7-11700K processor @ 3.60 GHz running Ubuntu 20.04.6 LTS.

In the evaluation, we test each of the three schemes (card swapping only, semihonest, and malicious) by benchmarking

1. Client registration time
2. Transaction processing time
3. Receipt distribution time (when applicable)
4. Balance settling time (when applicable)

Both client and server overhead times are reported in the output. When there are multiple lines of output for a given benchmark, the value (in parentheses) at the top of the section specifies which value is being varied. The value of this variable is listed in the left-most column of each output line.

## Installation

This project is built in Rust. Dependencies are listed in `Cargo.toml`.

To run the benchmarks reported in the paper, navigate to the LoyaltyPointsCrypto folder, and run `cargo run --release`.

### Android

To run on Android, first install [Termux](https://termux.dev/en/), and then install Rust as follows:

````
pkg install rust
````

Then follow the instructions above. You will need to place the project file within your home directory; to do so, you may need to allow Termux permission access to your files and media.