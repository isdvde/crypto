import os
import pickle
import datetime
import hashlib
import json
import requests
from uuid import getnode as get_mac
from flask import Flask, jsonify, request
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.wallets = []
        self.create_block(proof=1, previous_hash="genesis")
        self.nodes = set()  # No puede haber nodos repetidos
        self.dataFile = "db.dat"
        self.folder = os.path.dirname(os.path.abspath(__file__))
        self.loadData()

    def loadData(self):
        data = f"{self.folder}/{self.dataFile}"
        if os.path.getsize(data) != 0:
            with open(data, "rb") as d:
                self.chain, self.wallets = pickle.load(d)

    def dumpData(self, data):
        file = f"{self.folder}/{self.dataFile}"
        with open(file, "wb") as f:
            pickle.dump([data, self.wallets], f, -1)

    def createWallet(self):
        keyPair = rsa.generate_private_key(
                public_exponent=65537, key_size=512)
        pk = keyPair.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode('utf-8')
        pub = keyPair.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH).decode('utf-8')
        self.addWallet(pub)
        return pk, pub

    def addWallet(self, pub):
        self.wallets.append(pub)


    def create_block(self, proof, previous_hash):
        block = {
                "index": len(self.chain) + 1,
                "timestamp": str(datetime.datetime.now),
                "proof": proof,
                "previous_hash": previous_hash,
                "transactions": self.transactions
                }

        # Vaciamos las transacciones por que ya se incluyeron en el bloque
        self.transactions = []
        # Solo se meteran las transacciones a la blockchain
        # cuando se minen bloques
        # Metemos el nuevo bloque a la cadena
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(
                new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        hash_block = hashlib.sha256(encoded_block).hexdigest()
        return hash_block

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            # Signifca que las cadena ha sido alterada
            if block["previous_hash"] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(
                proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != "0000":
                return False
            previous_block = block
            block_index += 1
        return True

    def add_transaction(self, sender, receiver, amount):
        self.transactions.append(
                {"sender": sender, "receiver": receiver, "amount": amount})
        previous_block = self.get_previous_block()
        # En que bloque sera incluida la transaccion
        return previous_block["index"] + 1

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)  # incluimos la url como nuevo nodo

    def replace_chain(self):
        # Reemplza al blockchaain por la cadena mas larga
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()["length"]
                chain = response.json()["chain"]
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain

        if longest_chain:
            self.chain = longest_chain
            return True
        return False


app = Flask(__name__)
# Creamos una nueva dirreccion y eliminamos los guiones
node_address = str(get_mac())
blockchain = Blockchain()


@app.route("/mine_block", methods=["GET"])
def mine_block():
    wallet = request.args.get("wallet")
    if wallet:
        previous_block = blockchain.get_previous_block()
        previous_proof = previous_block['proof']
        proof = blockchain.proof_of_work(previous_proof)
        previous_hash = blockchain.hash(previous_block)
        blockchain.add_transaction(
                sender=node_address, receiver=wallet, amount=10)
        block = blockchain.create_block(proof, previous_hash)
        response = {
            "message": "Mined Block",
            "index": block["index"],
            "timestamp": block["timestamp"],
            "proof": block["proof"],
            "previous_hash": block["previous_hash"],
            "transactions": block["transactions"]
        }
        blockchain.dumpData(blockchain.chain)
        return jsonify(response), 200
    else:
        return 'Debe pasar la wallet para minar', 400



@app.route("/get_chain", methods=["GET"])
def get_chain():
    response = {
        "chain": blockchain.chain,
        "length": len(blockchain.chain)
    }
    return jsonify(response), 200


@app.route("/is_valid", methods=["GET"])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {"message": "Todo Correcto"}
    else:
        response = {"messahe": "La cadena no es valida"}
    return jsonify(response), 200


@app.route("/add_transaction", methods=["POST"])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in json for key in transaction_keys):
        return 'Faltan algunos elementos de la transacción', 400
    index = blockchain.add_transaction(
            json['sender'], json['receiver'], json['amount'])
    response = {'message': f'La transacción será añadida al bloque {index}'}
    return jsonify(response), 201


@app.route("/connect_node", methods=["POST"])
def connect_node():
    json = request.get_json()
    nodes = json.get("nodes")
    if nodes is None:
        return "No hay nodos en tu blockchain a incluir", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {
        "message": "Todos los nodos conectados",
        "Total_Nodes": list(blockchain.nodes)
    }
    return jsonify(response), 200


@app.route("/replace_chain", methods=["GET"])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {
            "message": "La cadena correcta ha sido actualizada",
            "new_chain": blockchain.chain
        }
    else:
        response = {
            "message": "Todo correcto,no hace falta actualizar",
            "new_chain": blockchain.chain
        }
    return jsonify(response), 200


@app.route("/create_wallet", methods=["GET"])
def createWallet():
    pk, pub = blockchain.createWallet()
    response = {"Public Key": pub, "Private Key": pk}
    return jsonify(response), 200





app.run(host='0.0.0.0', port=5000)
