import _crypto
from crypto import *
import random, time

# Round to thousandths (3 decimal points) of a millisecond
def round_to_3(num):
        return round(num, 3)

""" Time client registration for both versions, averaging over
    <n_clients> """
print("---------------------------")
print("--- Client Registration ---")
print("---------------------------")

# Record of how long it takes
points_client, points_server = 0, 0
base_client, base_server = 0, 0

n_clients = 10000
for handle_points in (True, False):
    server = Server(handle_points=handle_points)
    clients = []

    start = time.time()
    for i in range(n_clients):
        barcode = random.randint(0, 10000000000)
        client = Client(barcode, handle_points=handle_points)
        clients.append(client)
    if handle_points:
        points_client = time.time() - start
    else:
        base_client = time.time() - start
    
    start = time.time()
    for client in clients:
        server.register_user(*client.register_with_server())
    if handle_points:
        points_server = time.time() - start
    else:
        base_server = time.time() - start

base_client_avg = round_to_3(1000 * base_client/n_clients)
base_server_avg = round_to_3(1000 * base_server/n_clients)
points_client_avg = round_to_3(1000 * points_client/n_clients)
points_server_avg = round_to_3(1000 * points_server/n_clients)
print("Base client\tBase server\tPoints client\tPoints server")
print("{:<16}{:<16}{:<16}{:<16}".format(base_client_avg, base_server_avg,
                                        points_client_avg, points_server_avg))

""" Time transaction processing time for both versions of the protocol,
    varying the number of users of the system from 5000 to 50,000. """
print("------------------------------")
print("--- Transaction Processing ---")
print("------------------------------")

n_txs = 500
max_users = 50000
min_users = 5000
step = 5000
    
# Initialize a system with a certain number of users,
# and time how long it takes to process <n_txs> transactions
print("Users\tBase client\tBase server\tPoints client\tPoints server")
for n_users in range(min_users, max_users+1, step):
    
    # Record of how long it takes
    points_client, points_server = 0, 0
    base_client, base_server = 0, 0
    for handle_points in (True, False):
        server = Server(handle_points=handle_points)

        # Initialise n_users clients and register with server
        clients = []
        for i in range(n_users):
            barcode = random.randint(0, 10000000000)
            client = Client(barcode, handle_points=handle_points)
            clients.append(client)
            server.register_user(*client.register_with_server())
        
        # Inform every user of the new merkle root
        for i in range(n_users):
            clients[i].update_state(*server.share_state())
        
        # Process transactions
        txs = []
        for i in range(n_txs):
            shopper_uid = random.randint(0, n_users-1)
            points_used = random.randint(0, 300)
            txs.append({'uid_s': shopper_uid, 'points': points_used})

        # -----------------------------
        start = time.time()
        for tx in txs:
            shopper = clients[tx['uid_s']]
            com = shopper.process_tx_hello()
            tx['com'] = com
        if handle_points:
            points_client += time.time() - start
        else:
            base_client += time.time() - start
        # -----------------------------
        
        # -----------------------------
        start = time.time()
        for tx in txs:
            com = tx['com']
            i_s = server.process_tx_hello_response(com)
            tx['i_s'] = i_s
        if handle_points:
            points_server += time.time() - start
        else:
            base_server += time.time() - start
        # -----------------------------

        # -----------------------------
        start = time.time()
        for tx in txs:
            i_s, com = tx['i_s'], tx['com']
            shopper = clients[tx['uid_s']]
            i_c, r = shopper.process_tx_compute_id(i_s, com)
            tx['i_c'] = i_c
            tx['r'] = r
        if handle_points:
            points_client += time.time() - start
        else:
            base_client += time.time() - start
        # -----------------------------
        
        # -----------------------------
        start = time.time()
        if handle_points:
            for tx in txs:
                i_c, r, com = tx['i_c'], tx['r'], tx['com']
                uid_b, barcode, pk_b, pi = server.process_tx_barcode_gen(i_c, r, com)
                tx['uid_b'], tx['barcode'], tx['pk_b'], tx['pi'] = uid_b, barcode, pk_b, pi
            points_server += time.time() - start
        else:
            for tx in txs:
                i_c, r, com = tx['i_c'], tx['r'], tx['com']
                uid_b, barcode, pi = server.process_tx_barcode_gen(i_c, r, com)
                tx['uid_b'], tx['barcode'], tx['pi'] = uid_b, barcode, pi
            base_server += time.time() - start
        # -----------------------------

        # -----------------------------
        start = time.time()
        if handle_points:
            for tx in txs:
                shopper = clients[tx['uid_s']]
                pi, barcode, points_used, pk_b, com = tx['pi'], tx['barcode'], tx['points'], tx['pk_b'], tx['com']
                cts, ctb, pi = shopper.process_tx(pi, barcode, points_used, pk_b, com)
                tx['cts'], tx['ctb'], tx['pi'] = cts, ctb, pi
            points_client += time.time() - start
        else:
            for tx in txs:
                shopper = clients[tx['uid_s']]
                barcode, pi, com = tx['barcode'], tx['pi'], tx['com']
                shopper.verify_merkle_proof(barcode, pi, com)
            base_client += time.time() - start
        # -----------------------------

        # Finish the protocol if we're handling points
        # -----------------------------
        if handle_points:
            start = time.time()
            for tx in txs:
                shopper_uid, cts, ctb, pi, com = tx['uid_s'], tx['cts'], tx['ctb'], tx['pi'], tx['com']
                server.process_tx(shopper_uid, cts, ctb, pi, com)
            points_server += time.time() - start
        # -----------------------------
    
    base_client_avg = round_to_3(1000 * base_client/n_txs)
    base_server_avg = round_to_3(1000 * base_server/n_txs)
    points_client_avg = round_to_3(1000 * points_client/n_txs)
    points_server_avg = round_to_3(1000 * points_server/n_txs)
    print("{:<8}{:<16}{:<16}{:<16}{:<16}".format(n_users, base_client_avg, base_server_avg,
                                      points_client_avg, points_server_avg))
    

""" Time balance settling time for the point tracking version of the protocol,
    varying the number of points in a balance from 0 to 1000. """
print("------------------------")
print("--- Balance Settling ---")
print("------------------------")

n_settles = 10
min_points = 0
max_points = 1000
step = 25

print("Points\tClient settle time\tServer settle time")
for points in range(min_points, max_points+1, step):

    server = Server(handle_points=True)
    client = Client(barcode=0, handle_points=True)
    server.register_user(*client.register_with_server())

    # Insert the correct number of points into the client's account
    ct = _crypto.elgamal_enc(client.pk_enc, points)[:2]
    server.users[0]['balance'] = _crypto.add_ciphertexts(server.users[0]['balance'], ct)
    balance = server.settle_balance_hello(0)

    # Repeat the settle procedure <n_settles> times
    proofs = []
    start = time.time()
    for i in range(n_settles):
        plaintext, pi = client.settle_balance(balance)
        proofs.append((plaintext, pi))
    client_settle_time = time.time() - start

    start = time.time()
    for i in range(n_settles):
        server.settle_balance_finalize(*proofs[i])
    server_settle_time = time.time() - start

    print("{:<8}{:<24}{}".format(points, round_to_3(1000 * client_settle_time/n_settles),
                                         round_to_3(1000 * server_settle_time/n_settles)))
