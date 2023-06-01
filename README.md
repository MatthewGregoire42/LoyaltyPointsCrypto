This code accompanies the paper CheckOut: User-Controlled Anonymization for Supermarket Loyalty Programs.

Raw data collected in our evaluation is reported in `data_client.txt` and `data_server.txt`. Client measurements were taken on a Moto G Stylus 5G running Android 11, and server measurements were taken on an Intel Core i7 @ 3.60 GHz running Ubuntu 20.04.6 LTS.

## Installation

To run the code, first rename the parent directory from `LoyaltyPointsCrypto` to `crypto`. The project is built in Rust and Python, and has the following dependencies:

* Maturin. To install, follow the instructions at https://www.maturin.rs/tutorial.html. Before installing the following Python libraries, start a Python virtual environment as described at the link.
* Cryptography (Python library): https://cryptography.io/en/latest/
* Pymerkle: https://github.com/fmerg/pymerkle

Once the dependencies are installed, run `maturin develop` (if that fails, try `maturin build`), and you will be able to run `python/crypto/benchmarks.py`.

### Android

To run on Android, first install [Termux](https://termux.dev/en/), and then install Rust, Python and pip as follows:

````
pkg install rust
pkg install python
pkg install pip
````

Then follow the instructions above. You will need to place the project file within your home directory; to do so, you may need to allow Termux permission access to your files and media.