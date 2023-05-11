import _crypto
import cryptography

"""
TODO:
1. write wrappers for the Rust crypto functions
2. write a simple benchmark file (just encrypt/decrypt one message? Maybe add a proof as well)
3. once that works, put it up on the Google cloud machine
"""

class Server:
    num_users = 0
    field = 0

    def __init__(self):
        pass

class Client:
    field = 0
    def __init__(self):
        pass

    def process_tx_hello(self):
        pass
    def process_tx_response(self):
        pass

    def settle_balance(self):
        pass

sk, pk = _crypto.elgamal_keygen()
print(pk, sk)
print("---")
ct = _crypto.elgamal_enc(pk, -17) # ct has y as is third value, scrape off before passing to dec
print(ct)
print("---")
pt = _crypto.elgamal_dec(sk, ct[:2])
print(pt)