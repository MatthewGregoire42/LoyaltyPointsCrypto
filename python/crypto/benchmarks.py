from crypto import *
import random, time

N_USERS = 1000
N_TXS = 500

server = Server()
clients = []

# Register users
register_start = time.time()
for i in range(N_USERS):
    barcode = random.randint(0, 10000000000)
    client = Client(barcode)
    clients.append(client)
    server.register_user(*client.register_with_server())
register_time = time.time() - register_start
print("Time to register", N_USERS, "users:", register_time)
print("Average:", register_time/N_USERS)

# Generate a transcript of (shopper, barcode) pairs, representing a transaction
# initiated by 'shopper' using the loyalty account of 'barcode'
transaction_start = time.time()
for i in range(N_TXS):
    shopper_uid = random.randint(0, N_USERS-1)
    barcode_uid = random.randint(0, N_USERS-1)
    points_used = random.randint(0, 300)
    
    shopper_client = clients[shopper_uid]

    # TODO: implement process_tx_hello_response on server side. This is a stand-in
    pkb = server.users[barcode_uid]['pk_enc']
    cts, ctb, pi = shopper_client.process_tx_response(points_used, pkb)
    server.process_tx(shopper_uid, barcode_uid, cts, ctb, pi)
transaction_time = time.time() - transaction_start
print("Time to process", N_TXS, "transactions:", transaction_time)
print("Average:", transaction_time/N_TXS)

# Settle balances
settle_start = time.time()
for uid in range(N_USERS):
    client = clients[uid]
    balance = server.settle_balance_hello(uid)
    plaintext, pi = client.settle_balance(balance)
    server.settle_balance_finalize(plaintext, pi)
settle_time = time.time() - settle_start
print("Time to settle", N_TXS, "between", N_USERS, "users:", settle_time)
print("Average per user:", settle_time/N_USERS)