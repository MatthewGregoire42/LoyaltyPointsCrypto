import _crypto
from cryptography.hazmat.primitives import hashes
import pymerkle
from random import SystemRandom
import os
import pickle

class Server:
    def __init__(self, handle_points=True):
        self.num_users = 0
        self.users = []
        self.merkle_tree = pymerkle.MerkleTree(algorithm='sha256', encoding='utf-8', security=True)
        self.tmp = {}
        self.handle_points = handle_points
    
    def register_user(self, barcode, pk_enc=None):
        if self.handle_points:
            init_balance = _crypto.elgamal_enc(pk_enc, 0)[:2]
            self.users.append({'barcode': barcode,
                            'uid': self.num_users,
                            'balance': init_balance,
                            'pk_enc': pk_enc})
            user_record = (self.num_users, barcode, pk_enc)
        else:
            self.users.append({'barcode': barcode,
                               'uid': self.num_users})
            user_record = (self.num_users, barcode)
        self.merkle_tree.append_entry(pickle.dumps(user_record))
        self.num_users += 1
    
    # Used to update clients about necessary public state information
    def share_state(self):
        return self.num_users, self.merkle_tree.root
    
    """
    Step 1 of a transaction request
    
    Input: shopper user ID, commitment to a chosed random ID
    Output: a server-chosen random ID
    """
    def process_tx_hello_response(self, com):
        # Choose a random index to send to the client
        rng = SystemRandom()
        i_s = rng.randrange(0, self.num_users)
        # Create a temporary record of state for this transaction, indexed by
        # the transaction ID number (client commitment)
        self.tmp[com] = {'i_s': i_s}
        return i_s

    """
    Step 2 of a transaction request

    Input: shopper UID, opened commitment contents: client-chosen random ID and mask
    Output: barcode owner's UID, barcode, and public key, and merkle inclusion proof
    """
    def process_tx_barcode_gen(self, i_c, r, tx_id):
        tmp = self.tmp[tx_id]

        # Recompute commitment and check that it matches.
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes(i_c))
        digest.update(r)
        com_test = digest.finalize()

        if tx_id != com_test:
            print("Error")
            return
                
        uid_b = (i_c + tmp['i_s']) % self.num_users

        tmp['uid_b'] = uid_b

        if self.handle_points:
            barcode, pk_b = self.users[uid_b]['barcode'], self.users[uid_b]['pk_enc']
            user_record = (uid_b, barcode, pk_b)
        else:
            barcode = self.users[uid_b]['barcode']
            user_record = (uid_b, barcode)

        pi = self.merkle_tree.prove_inclusion(pickle.dumps(user_record))

        if self.handle_points:
            return uid_b, barcode, pk_b, pi
        else:
            return uid_b, barcode, pi

    """
    Step 3 of a transaction request
    """
    def process_tx(self, shopper, cts, ctb, pi, tx_id):
        tmp = self.tmp[tx_id]

        if (not _crypto.zk_ct_eq_verify(pi)):
            print("Error")
            return
        
        barcode = tmp['uid_b']
        
        self.users[shopper]['balance'] = _crypto.add_ciphertexts(self.users[shopper]['balance'], cts)
        self.users[barcode]['balance'] = _crypto.add_ciphertexts(self.users[barcode]['balance'], ctb)

        # Clear the temporary state for this transaction
        del self.tmp[tx_id]

    def settle_balance_hello(self, uid):
        return self.users[uid]['balance']
    
    def settle_balance_finalize(self, plaintext, pi):
        return _crypto.zk_ct_dec_verify(pi)

class Client:
    def __init__(self, barcode, handle_points=True):
        self.handle_points = handle_points
        self.barcode = barcode
        self.num_users = 1
        self.merkle_root = None
        self.tmp = {}

        if handle_points:
            self.sk_enc, self.pk_enc = _crypto.elgamal_keygen()
            with open('./scratchpad.txt', 'wb') as file:
                file.write(pickle.dumps(self.pk_enc))
        else:
            self.pk_enc = None

    
    def register_with_server(self):
        return self.barcode, self.pk_enc

    def update_state(self, num_users, merkle_root):
        self.num_users = num_users
        self.merkle_root = merkle_root

    """
    Step 1 of a transaction request

    Input: N/A
    Output: commitment to a randomly chosen user ID
    """
    def process_tx_hello(self):
        # Commit to a random index and send it to the server
        rng = SystemRandom()
        i_c = rng.randrange(0, self.num_users)
        r = os.urandom(64)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes(i_c))
        digest.update(r)

        com = digest.finalize()

        # Temporarily store state relevant to this transaction. For testing purposes, we require
        # the client to be able to have multiple in-process transactions at the same time.
        tx_id = com
        self.tmp[tx_id] = {'i_c': i_c, 'r': r}

        return com
    
    """
    Step 2 of a transaction request

    Input: server's randomly chosen barcode UID
    Output: opened commitment to client-chosed barcode UID
    """
    def process_tx_compute_id(self, i_s, tx_id):
        tmp = self.tmp[tx_id]

        i = (tmp['i_c'] + i_s) % self.num_users

        tmp['uid_b'] = i
        return tmp['i_c'], tmp['r']

    def verify_merkle_proof(self, barcode, pi, tx_id, pkb=None):
        bid = self.tmp[tx_id]['uid_b']
        if self.handle_points:
            pymerkle.verify_inclusion(pickle.dumps((bid, barcode, pkb)), self.merkle_root, pi)
        else:
            # If we don't need to handle points, we just need to verify the proof and
            # this is the last function we call.
            pymerkle.verify_inclusion(pickle.dumps((bid, barcode)), self.merkle_root, pi)
            del self.tmp[tx_id]
        
    """
    Step 3 of a transaction request
    """
    def process_tx(self, pi, barcode, points, pkb, tx_id):
        tmp = self.tmp[tx_id]

        # Verify Merkle proof that the agreed upon index is in the tree
        self.verify_merkle_proof(barcode, pi, tx_id, pkb)

        # Encrypt the number of points under both public keys
        cts = _crypto.elgamal_enc(self.pk_enc, -1*points)
        cts_data = _crypto.CompressedTxCiphertextData(cts[:2], cts[2], -1*points, self.pk_enc)

        ctb = _crypto.elgamal_enc(pkb, points)
        ctb_data = _crypto.CompressedTxCiphertextData(ctb[:2], ctb[2], points, pkb)

        # Generate a zero knowledge proof that these encrypt the same value
        pi = _crypto.zk_ct_eq_prove(cts_data, ctb_data)

        # Clear temporary state for this transaction
        del self.tmp[tx_id]

        return cts[:2], ctb[:2], pi

    def settle_balance(self, ct):
        plaintext = _crypto.elgamal_dec(self.sk_enc, ct)
        pi = _crypto.zk_ct_dec_prove(ct, plaintext, self.sk_enc, self.pk_enc)

        return plaintext, pi