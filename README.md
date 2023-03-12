# Doricoin
## Criptomoneda desarrolada en Python

###### Doricoin es una criptomoneda sencilla desarrollada en *Python* el cual permite minar generando bloques utilizando un algoritmo asimetrico simple en la generacion de hash.

Esta desarrollada en un solo modulo para su portabilidad y distibucion en diferentes **Nodos**

### Caracteristicas
- Blockchain
- Minado 
- Generacion de bloque
- Wallet
- Inclusion de multiples nodos
- Sincronizacion de Cadena
- Transacciones
- Validacion de wallets

## Uso

El modulo funciona usando el protocolo http como servidor web, recibiendo peticiones mediante una API la cual procesa todas las transacciones.

#### /mine_block?wallet=
Metodo *GET*
Argumentos:
- wallet = string

Se encarga de minar, generando el bloque mediante un algoritmo asimetrico el cual pretende generar un hash donde los primeros 5 digitos sean igual a 0, como resultado devolvera el bloque generado y asignara la remuneracion a la wallet identificada.
```python
@app.route("/mine_block", methods=["GET"])
def mine_block():
    wallet = request.args.get("wallet")
    if blockchain.is_wallet_valid(wallet):
        previous_block = blockchain.get_previous_block()
        previous_proof = previous_block['proof']
        proof, time = blockchain.proof_of_work(previous_proof)
        previous_hash = blockchain.hash(previous_block)
        blockchain.add_transaction(
                sender=node_address, receiver=wallet, amount=(time/proof)/time)
        block = blockchain.create_block(proof, previous_hash)
        response = {
                "message": "Mined Block",
                "index": block["index"],
                "timestamp": block["timestamp"],
                "proof": block["proof"],
                "previous_hash": block["previous_hash"],
                "transactions": block["transactions"]}
        blockchain.makeTransaction(block['transactions'])
        blockchain.dumpData(blockchain.chain, blockchain.wallets)
        return jsonify(response), 200
    else:
        return ('Debe pasar la wallet para minar', 400)
```

#### /get_chain
Metodo *GET*
Se encarga de mostrar la cadena generada por la mineria de bloques, como resultado devolvera un arreglo con todos los nodos en secuencia y el tamaño.
```python
@app.route("/get_chain", methods=["GET"])
def get_chain():
    response = {
        "chain": blockchain.chain,
        "length": len(blockchain.chain)
    }
    return jsonify(response), 200
```

#### /get_chain
Metodo *GET*
Verifica si la cadena del nodo es valida comparandola con la cadena de los demas nodos, como resultado devuelve un mensaje.
```python
@app.route("/is_valid", methods=["GET"])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {"message": "Todo Correcto"}
    else:
        response = {"messahe": "La cadena no es valida"}
    return jsonify(response), 200
```

#### /add_transaction
Metodo *POST*
Parametros:

- sender: string. El emisor de la transaccion.
- receiver: string. El receptor de la transaccion.
- amount: int. Cantidad a ser transferida.
- key: string. Llave de validacion de wallet que emitira la transaccion

Genera una transaccion de moneda desde una wallet a otra, utilizando una autenticacion mediante la llave privada generada al momento de crear una wallet. Las transacciones se hacen y quedan a espera de ser consolidadas, esto ultimo ocurre cuando se genera un bloque nuevo.
```python
@app.route("/add_transaction", methods=["POST"])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount', 'key']
    if not all(key in json for key in transaction_keys):
        return 'Faltan algunos elementos de la transacción', 400
    if blockchain.rsaCheckSign(json['key'], json['sender']):
        index = blockchain.add_transaction(
                json['sender'], json['receiver'], json['amount'])
        response = {'message': f'La transacción será añadida al bloque {index}'}
        return jsonify(response), 201
    else:
        return "Wallet no valida", 400
```

#### /connect_node
Metodo *POST*
Parametros:
- nodes: array. Lista de nodos en la red.

Conecta nuestro nodo a los demas nodos para sincronizar la cadena, wallets y generar transacciones entre ellos. Este verifica la url de los demas y los añade a la blockchain.
```python
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
```

#### /replace_chain
Metodo *GET*
Reemplaza la cadena del nodo con la cadena mas larga que se encuentre en la red de nodos, por lo tando debe hacerce despues de entrar en una red. Como resultado devuelve la cadena actulaizada.
```python
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
```

#### /create_wallet
Metodo *GET*
Genera una nueva wallet en la blockchain, lista para recibir o generar transacciones. La wallet consta de dos partes, la direccion de la wallet, una firma y una llave. La direccion de la wallet y la llave privada son la llaves publica y privada de un par respetivamente, estas se encuetran encriptadas en formato hash lo cual permite una mejor portabilidad. La firma es un texto cifrado, que solo puede ser obtenido mediante la llave privada que no debe ser comparrida, esto le permite a la wallet necesitar autenticacion para realizar transacciones. Como resultado devolvera la direccion de la wallet y la llave privada que debe ser guardada ya que solo se muestra al generar una wallet.  
```python
@app.route("/create_wallet", methods=["GET"])
def createWallet():
    pk, wallet = blockchain.createWallet()
    response = {"Wallet": wallet, "Private Key": pk}
    blockchain.dumpData(blockchain.chain, blockchain.wallets)
    return jsonify(response), 200
```

#### /check_wallet
Metodo *POST*
Parametros:
- wallet: string. Direccionde la wallet
- key: string. Llave privada para autenticar

Genera la informacion de la wallet para ser mostrada, como resultado devolvera la wallet con su direccion y balance
```python
@app.route("/check_wallet", methods=["POST"])
def check_wallet():
    def find(wallet):
        for w in blockchain.wallets:
            if w['pub'] == wallet:
                return w
    json = request.get_json()
    transaction_keys = ['wallet', 'key']
    if not all(key in json for key in transaction_keys):
        return 'Faltan algunos elementos de la wallet', 400
    if blockchain.rsaCheckSign(json['key'], json['wallet']):
        wallet = find(json['wallet'])
        response = {
                'wallet': wallet['pub'],
                'balance': wallet['balance']}
    else:
        response = {'message': 'Wallet no valida'}
    return jsonify(response), 201
```

## Instalacion

Para la instalalcion del nodo se necesitan los paquetes de python:
- FLask
- requests
- rsa
```sh
python3 -m pip install Flask requests rsa
```
Para ejecutar la aplicacion en modo debug:
```sh
python -m flask -A nodo.py run --debug
```

Para ejecutar la aplicacion en normal:
```sh
python nodo.py
```

**Esto ejecutara la aplicacion en el puerto 5000 del host**
