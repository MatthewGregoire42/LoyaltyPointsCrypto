from crypto import *
import _crypto
import random, time

N_USERS = 10000
N_TXS = 40000
N_DECS = 10

print("++++++++++++++++++++++++++++++++++++++++++")
print("Number of users:", N_USERS)
print("Number of transactions performed:", N_TXS)
print("++++++++++++++++++++++++++++++++++++++++++")

server = Server(testing=True)
clients = []

# Register users
print("User registration")
print("******************************************")
# ------------------------------------------
client_init_start = time.time()
# ------------------------------------------
for i in range(N_USERS):
    barcode = random.randint(0, 10000000000)
    client = Client(barcode, testing=True)
    clients.append(client)
# ------------------------------------------
client_init_time = time.time() - client_init_start
print("Time to intialize", N_USERS, "users:", client_init_time)
print("Average:", client_init_time/N_USERS)
print("------------------------------------------")
# ------------------------------------------

# ------------------------------------------
client_register_start = time.time()
# ------------------------------------------
for i in range(N_USERS):
    server.register_user(*clients[i].register_with_server())
# ------------------------------------------
client_init_time = time.time() - client_init_start
print("Time to register", N_USERS, "users:", client_init_time)
print("Average:", client_init_time/N_USERS)
print("------------------------------------------")
# ------------------------------------------

# Update all shoppers to get an updated view of the system
server_state = server.share_state()
for i in range(N_USERS):
    clients[i].update_state(*server_state)

# Generate a transcript of (shopper, points) pairs, representing a transaction
# initiated by 'shopper' and using 'points' loyalty points
txs = []
for i in range(N_TXS):
    shopper_uid = random.randint(0, N_USERS-1)
    points_used = random.randint(0, 300)
    txs.append({'uid_s': shopper_uid, 'points': points_used})

print("Transaction processing")
print("******************************************")
# ------------------------------------------
transaction_c1_start = time.time()
# ------------------------------------------
for i in range(N_TXS):
    shopper_uid = txs[i]['uid_s']
    shopper_client = clients[shopper_uid]
    com = shopper_client.process_tx_hello(tx_id=i)
    txs[i]['com'] = com
# ------------------------------------------
transaction_c1_time = time.time() - transaction_c1_start
print("Time for clients to generate commitments for", N_TXS, "transactions:", transaction_c1_time)
print("Average:", transaction_c1_time/N_TXS)
print("------------------------------------------")
# ------------------------------------------

# ------------------------------------------
transaction_s1_start = time.time()
# ------------------------------------------
for i in range(N_TXS):
    shopper_uid, com = txs[i]['uid_s'], txs[i]['com']
    i_s = server.process_tx_hello_response(shopper_uid, com, tx_id=i)
    txs[i]['i_s'] = i_s
# ------------------------------------------
transaction_s1_time = time.time() - transaction_s1_start
print("Time for server to respond with randomness for", N_TXS, "transactions:", transaction_s1_time)
print("Average:", transaction_s1_time/N_TXS)
print("------------------------------------------")
# ------------------------------------------

# ------------------------------------------
transaction_c2_start = time.time()
# ------------------------------------------
for i in range(N_TXS):
    shopper_uid, i_s = txs[i]['uid_s'], txs[i]['i_s']
    shopper_client = clients[shopper_uid]
    i_c, r = shopper_client.process_tx_compute_id(i_s, tx_id=i)
    txs[i]['i_c'], txs[i]['r'] = i_c, r
# ------------------------------------------
transaction_c2_time = time.time() - transaction_c2_start
print("Time for client to compute barcode and reveal commitments for", N_TXS, "transactions:", transaction_c2_time)
print("Average:", transaction_c2_time/N_TXS)
print("------------------------------------------")
# ------------------------------------------

# ------------------------------------------
transaction_s2_start = time.time()
# ------------------------------------------
for i in range(N_TXS):
    shopper_uid, i_c, r = txs[i]['uid_s'], txs[i]['i_c'], txs[i]['r']
    uid_b, barcode, pk_b, pi = server.process_tx_barcode_gen(shopper_uid, i_c, r, tx_id=i)
    txs[i]['uid_b'], txs[i]['barcode'], txs[i]['pk_b'], txs[i]['pi'] = uid_b, barcode, pk_b, pi
# ------------------------------------------
transaction_s2_time = time.time() - transaction_s2_start
print("Time for server to compute barcode and merkle proof for", N_TXS, "transactions:", transaction_s2_time)
print("Average:", transaction_s2_time/N_TXS)
print("------------------------------------------")
# ------------------------------------------

# ------------------------------------------
transaction_c3_start = time.time()
# ------------------------------------------
for i in range(N_TXS):
    shopper_uid, pi, barcode, points_used, pk_b = txs[i]['uid_s'], txs[i]['pi'], txs[i]['barcode'], txs[i]['points'], txs[i]['pk_b']
    shopper_client = clients[shopper_uid]
    cts, ctb, pi = shopper_client.process_tx(pi, barcode, points_used, pk_b, tx_id=i)
    txs[i]['cts'], txs[i]['ctb'], txs[i]['pi'] = cts, ctb, pi
# ------------------------------------------
transaction_c3_time = time.time() - transaction_c2_start
print("Time for client to verify merkle proof and compute encryptions and ZK proofs for", N_TXS, "transactions:", transaction_c3_time)
print("Average:", transaction_c3_time/N_TXS)
print("------------------------------------------")
# ------------------------------------------

# ------------------------------------------
transaction_s3_start = time.time()
# ------------------------------------------
for i in range(N_TXS):
    shopper_uid, cts, ctb, pi = txs[i]['uid_s'], txs[i]['cts'], txs[i]['ctb'], txs[i]['pi']
    server.process_tx(shopper_uid, cts, ctb, pi, tx_id=i)
# ------------------------------------------
transaction_s3_time = time.time() - transaction_s3_start
print("Time for server to verify ZK proofs for", N_TXS, "transactions:", transaction_s3_time)
print("Average:", transaction_s3_time/N_TXS)
print("------------------------------------------")
# ------------------------------------------

# Settle balances

balances = []
for uid in range(N_USERS):
    balance = server.settle_balance_hello(uid)
    balances.append(balance)

pt_pis = []
print("Balance settling")
print("******************************************")
# ------------------------------------------
settle_client_start = time.time()
# ------------------------------------------
for uid in range(N_USERS):
    client = clients[uid]
    balance = balances[uid]
    plaintext, pi = client.settle_balance(balance)
    pt_pis.append((plaintext, pi))
    # server.settle_balance_finalize(plaintext, pi)
# ------------------------------------------
settle_client_time = time.time() - settle_client_start
print("Time for clients to decrypt and make ZK proofs for ", N_TXS, "transactions between", N_USERS, "users:", settle_client_time)
print("Average per user:", settle_client_time/N_USERS)
print("------------------------------------------")
# ------------------------------------------

# ------------------------------------------
settle_server_start = time.time()
# ------------------------------------------
for uid in range(N_USERS):
    plaintext, pi = pt_pis[uid]
    server.settle_balance_finalize(plaintext, pi)
# ------------------------------------------
settle_server_time = time.time() - settle_server_start
print("Time for server to verify ZK proofs for ", N_USERS, "balance settlements:", settle_server_time)
print("Average per user:", settle_server_time/N_USERS)
# ------------------------------------------

print("******************************************")
print("******************************************")
print("Decryption times by number of points")
print("Average over", N_DECS, "iterations")

max_points = 1000

cts = []
sk, pk = _crypto.elgamal_keygen()
# Encrypt all possible point values from 0 to 1000
for i in range(max_points+1):
    cts.append(_crypto.elgamal_enc(pk, i)[:2])

for i in range(max_points+1):
    ct = cts[i]
    # ------------------------------------------
    dec_start = time.time()
    # ------------------------------------------
    # Repeat decryption multiple times to get a more accurate measurement
    for j in range(N_DECS):
        pt = _crypto.elgamal_dec(sk, ct)
    # ------------------------------------------
    dec_time = time.time() - dec_start
    print(i, dec_time/N_DECS)
    # ------------------------------------------