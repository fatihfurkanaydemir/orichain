import os
import sys
import signal
import atexit
from hashlib import sha256
import json
import time
from flask import Flask, request
from flask_cors import CORS
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from base64 import b64encode, b64decode
from apscheduler.schedulers.background import BackgroundScheduler

# Helper class for cryptographic signing and verifying functions
class Crypto:
  def key_pair():
      random_generator = Random.new().read
      key = RSA.generate(2048, random_generator)
      private, public = key, key.publickey()
      return public, private

  def import_key(externKey):
      return RSA.importKey(externKey)

  def get_public_key(priv_key):
      return priv_key.publickey()

  def sign(message, priv_key):
      signer = PKCS1_v1_5.new(priv_key)
      digest = SHA256.new()
      digest.update(message)
      return signer.sign(digest)

  def verify(message, signature, pub_key):
      signer = PKCS1_v1_5.new(pub_key)
      digest = SHA256.new()
      digest.update(message)
      return signer.verify(digest, signature)
  
class Transaction:
    """
    Transaction class representing a product's transfer from one person to another
    """
    def __init__(self, from_addr, to_addr, product_serial, timestamp, signature = None):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.product_serial = product_serial
        self.timestamp = timestamp
        self.signature = signature

    def sign(self, private_key):
       """
       Sign the transaction
       """
       self.signature = b64encode(Crypto.sign(bytes(self.product_serial, 'utf-8'), private_key)).decode()

    def verify(self, public_key):
        """
        Verify the transaction
        """
        return Crypto.verify(bytes(self.product_serial, 'utf-8'), b64decode(bytes(self.signature, 'utf-8')), public_key)
    
    def to_json(self):
        return json.dumps(self.__dict__, sort_keys=True)
    
    def from_json(json):
        return Transaction(
            json["from_addr"],
            json["to_addr"],
            json["product_serial"],
            json["timestamp"],
            json["signature"]
        )

class Block:
    """
    Class representing a block of blockchain holding relevant information
    """
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def compute_hash(self):
        """
        A function that returns the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:
    # difficulty of our PoW algorithm
    difficulty = 4

    def __init__(self, chain=None):
        self.unconfirmed_transactions = []
        self.chain = chain
        if self.chain is None:
            self.chain = []
            self.create_genesis_block()

    def create_genesis_block(self):
        """
        A function to generate genesis block and appends it to
        the chain. The block has index 0, previous_hash as 0, and
        a valid hash.
        """
        genesis_block = Block(0, [], 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        """
        A function that adds the block to the chain after verification.
        Verification includes:
        * Checking if the proof is valid.
        * The previous_hash referred in the block and the hash of latest block
          in the chain match.
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            raise ValueError("Previous hash incorrect")

        if not Blockchain.is_valid_proof(block, proof):
            raise ValueError("Block proof invalid")

        block.hash = proof
        self.chain.append(block)

    @staticmethod
    def proof_of_work(block):
        """
        Function that tries different values of nonce to get a hash
        that satisfies our difficulty criteria.
        """
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    def get_product_history(self, product_serial):
        """
        Get the transaction history of a product
        """
        history = []
        for block in self.chain[::-1]:
            for tx in block.transactions[::-1]:
                if(Transaction.from_json(json.loads(tx)).product_serial == product_serial):
                    history.insert(0, tx)
    
        return history
    
    def get_last_transaction_of_product(self, product_serial):
        """
        Get the latest transaction of a product
        """
        # Check unconfirmed transactions as well
        for tx in self.unconfirmed_transactions:
                if(Transaction.from_json(json.loads(tx)).product_serial == product_serial):
                    return tx
                
        # Check blockchain
        for block in self.chain[::-1]:
            for tx in block.transactions:
                if(Transaction.from_json(json.loads(tx)).product_serial == product_serial):
                    return tx
    
        return None


    @classmethod
    def is_valid_proof(cls, block, block_hash):
        """
        Check if block_hash is valid hash of block and satisfies
        the difficulty criteria.
        """
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash
            # remove the hash field to recompute the hash again
            # using `compute_hash` method.
            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break

            block.hash, previous_hash = block_hash, block_hash

        return result

    def mine(self):
        """
        This function serves as an interface to add the pending
        transactions to the blockchain by adding them to the block
        and figuring out Proof Of Work.
        """
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []

        return True


app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}})

# the node's copy of blockchain
blockchain = Blockchain()

# the address to other participating members of the network
peers = set()

# endpoint to submit a new transaction. This will be used by
# our application to add new transaction to the blockchain
@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["product_serial", "from_private_key", "to_addr"]

    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 404
        
    # Get latest transaction of product
    last_tx = blockchain.get_last_transaction_of_product(tx_data["product_serial"])
    if(not last_tx): return "Product doesn't exist", 404

    # Convert private key from json to RSA key pair
    private_key = Crypto.import_key(bytes(tx_data["from_private_key"].replace('\\n', '\n'), 'utf-8'))
    public_key = private_key.public_key()

    # Convert latest transaction to Transaction object
    tx = Transaction.from_json(json.loads(last_tx))
    # Check if the seller is the owner of this product
    if(tx.to_addr != public_key.export_key().decode()): return "Unauthorized sale", 401
    # Check if seller is trying to sell product to self
    if(tx.to_addr == tx_data["to_addr"].replace('\\n', '\n')): return "Self sales not allowed", 400

    # Create new transaction and sign it with seller's key
    new_tx = Transaction(public_key.export_key().decode(), tx_data["to_addr"].replace('\\n', '\n'), tx_data["product_serial"], time.time())
    new_tx.sign(private_key)

    # Get public key of last transaction's receiver and verify the person selling this product is
    # the same person as last received this product
    verifier_key = RSA.import_key(tx.to_addr)
    if(not new_tx.verify(verifier_key)): return "Verification failed, Unouthorized", 401

    blockchain.add_new_transaction(new_tx.to_json())

    return "Success", 201

# This endpoint is called from frontend to add a new product to
# the blockchain
@app.route('/add_product', methods=['POST'])
def add_product():
    tx_data = request.get_json()
    required_fields = ["product_serial", "private_key"]

    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 404

    # Check if the product already exists
    product_exists = blockchain.get_last_transaction_of_product(tx_data["product_serial"])
    if(product_exists): return "Product already exists", 400

    # Generate RSA keypair from provided private key
    private_key = Crypto.import_key(bytes(tx_data["private_key"].replace('\\n', '\n'), 'utf-8'))
    public_key = private_key.public_key()

    # Create new transaction from seller to seller itself again
    # Owner of a newly introduced product is the person who introduces it
    tx = Transaction(public_key.export_key().decode(), public_key.export_key().decode(), tx_data["product_serial"], time.time())
    tx.sign(private_key)

    blockchain.add_new_transaction(tx.to_json())

    return "Success", 201


# chain_file_name = os.environ.get('DATA_FILE')


def create_chain_from_dump(chain_dump):
    generated_blockchain = Blockchain()
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            continue  # skip genesis block
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        generated_blockchain.add_block(block, proof)
    return generated_blockchain


# endpoint to return the node's copy of the chain.
# Our application will be using this endpoint to query
# all the posts to display.
@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})

# Endpoint to get history of a product
@app.route('/history/<product_serial>', methods=['GET'])
def get_history(product_serial):
    history = blockchain.get_product_history(product_serial)
    if(len(history) == 0):
        return "Product not found", 404
    
    return json.dumps(history), 200

scheduler = BackgroundScheduler()

# endpoint to request the node to mine the unconfirmed
# transactions (if any). We'll be using it to initiate
# a command to mine from our application itself.
# @app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    result = blockchain.mine()
    if not result:
        print("No transactions to mine")
    else:
        # Making sure we have the longest chain before announcing to the network
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            # announce the recently mined block to the network
            announce_new_block(blockchain.last_block)
        print("Block #{} is mined.".format(blockchain.last_block.index))


# Timer based mining for demo purposes
scheduler.add_job(func=mine_unconfirmed_transactions, trigger="interval", seconds=10)
scheduler.start()

# endpoint to add new peers to the network.
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Add the node to the peer list
    peers.add(node_address)

    # Return the consensus blockchain to the newly registered node
    # so that he can sync
    return get_chain()


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    Internally calls the `register_node` endpoint to
    register current node with the node specified in the
    request, and sync the blockchain as well as peer data.
    """
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}

    # Make a request to register with remote node and obtain information
    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        # update chain and the peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        peers.remove(request.host_url)
        peers.add(node_address)
        return "Registration successful", 200
    else:
        # if something goes wrong, pass it on to the API response
        return response.content, response.status_code


# endpoint to add a block mined by someone else to
# the node's chain. The block is first verified by the node
# and then added to the chain.
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']

    try:
        blockchain.add_block(block, proof)
    except ValueError as e:
        return "The block was discarded by the node: " + e.str(), 400

    print("Block added to the chain")
    return "Block added to the chain", 201


# endpoint to query unconfirmed transactions
@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)


def consensus():
    """
    Our consnsus algorithm. If a longer valid chain is
    found, our chain is replaced with it.
    """
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        response = requests.get('{}chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        print("Replaced our's with a longer other chain")
        blockchain = longest_chain
        return True

    return False


def announce_new_block(block):
    """
    A function to announce to the network once a block has been mined.
    Other blocks can simply verify the proof of work and add it to their
    respective chains.
    """
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block.__dict__, sort_keys=True),
                      headers=headers)

#app.run(debug=True, port=8000)
