import _crypto
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

"""
TODO:
1. write wrappers for the Rust crypto functions
2. write a simple benchmark file (just encrypt/decrypt one message? Maybe add a proof as well)
3. once that works, put it up on the Google cloud machine
"""

class Server:

    def __init__(self):
        self.num_users = 0
        self.users = []
        self.merkle_tree = None
    
    def register_user(self, barcode, pk_enc, pk_sig):
        init_balance = _crypto.elgamal_enc(pk_enc, 0)[:2]
        self.users.append({'barcode': barcode,
                           'uid': self.num_users,
                           'balance': init_balance,
                           'pk_enc': pk_enc,
                           'pk_sig': pk_sig})
        self.num_users += 1
    
    def process_tx_hello_response(self):
        pass # TODO: incorporate Rachel's implementation here

    def process_tx(self, shopper, barcode, cts, ctb, pi):
        if (not _crypto.zk_ct_eq_verify(pi)):
            return
        
        self.users[shopper]['balance'] = _crypto.add_ciphertexts(self.users[shopper]['balance'], cts)
        self.users[barcode]['balance'] = _crypto.add_ciphertexts(self.users[barcode]['balance'], ctb)  

    def settle_balance_hello(self, uid):
        return self.users[uid]['balance']
    
    def settle_balance_finalize(self, plaintext, pi):
        return _crypto.zk_ct_dec_verify(pi)

class Client:
    def __init__(self, barcode):
        self.sk_enc, self.pk_enc = _crypto.elgamal_keygen()
        self.sk_sig = Ed25519PrivateKey.generate()
        self.pk_sig = self.sk_sig.public_key()
        self.barcode = barcode
    
    def register_with_server(self):
        return self.barcode, self.pk_enc, self.pk_sig

    # Request a transaction from the server
    def process_tx_hello(self):
        pass

    def process_tx_response(self, points, pkb):
        cts = _crypto.elgamal_enc(self.pk_enc, -1*points)
        cts_data = _crypto.CompressedTxCiphertextData(cts[:2], cts[2], -1*points, self.pk_enc)

        ctb = _crypto.elgamal_enc(pkb, points)
        ctb_data = _crypto.CompressedTxCiphertextData(ctb[:2], ctb[2], points, pkb)

        pi = _crypto.zk_ct_eq_prove(cts_data, ctb_data)

        return cts[:2], ctb[:2], pi

    def settle_balance(self, ct):
        plaintext = _crypto.elgamal_dec(self.sk_enc, ct)
        pi = _crypto.zk_ct_dec_prove(ct, plaintext, self.sk_enc, self.pk_enc)

        return plaintext, pi