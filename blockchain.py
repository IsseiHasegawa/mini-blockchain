import hashlib
import json
import logging
import sys
import time

from ecdsa import NIST256p
from ecdsa import VerifyingKey

import utils

MINING_DIFFICULTY = 3
MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1.0

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

class BlockChain(object):
    def __init__(self, blockchain_address = None, port=None):
        """
        Initialize a new blockchain instance.

        Creates an empty transaction pool and blockchain,
        and generates the genesis block.

        Args:
            blockchain_address (str, optional): The address used to receive mining rewards.
            port (int, optional): The port number on which the node is running.
        """
        self.transaction_pool = []
        self.chain = []
        self.create_block(0, self.hash({}))
        self.blockchain_address = blockchain_address
        self.port = port

    def create_block(self, nonce, previous_hash):
        """
        Create a new block and add it to the blockchain.

        The block includes a timestamp, pending transactions,
        a nonce, and the hash of the previous block.
        After the block is created, the transaction pool is cleared.

        Args:
            nonce (int): The nonce value obtained from the proof-of-work.
            previous_hash (str): The hash of the previous block in the chain.

        Returns:
            dict: The newly created block.
        """
        block = utils.sorted_dict_by_key({
            'timestamp': time.time(),
            'transactions': self.transaction_pool,
            'nonce': nonce,
            'previous_hash': previous_hash
        })
        self.chain.append(block)
        self.transaction_pool = []
        return block
    
    def hash(self, block):
        """
        Compute the SHA-256 hash of a block.

        The block is first serialized into a JSON string with
        its keys sorted to ensure deterministic hashing.

        Args:
            block (dict): The block data to be hashed.

        Returns:
            str: The SHA-256 hash of the block as a hexadecimal string.
        """
        sorted_block = json.dumps(block, sort_keys=True)
        return hashlib.sha256(sorted_block.encode()).hexdigest()
    
    def add_transaction(self, sender_blockchain_address,
                        recipient_blockchain_address, value,
                            sender_public_key=None, signature=None):
        """
        Add a new transaction to the transaction pool.

        For regular transactions, the transaction signature is verified
        using the sender's public key before being added.
        Mining reward transactions are added without signature verification.

        Args:
            sender_blockchain_address (str): The blockchain address of the sender.
            recipient_blockchain_address (str): The blockchain address of the recipient.
            value (float): The amount to be transferred.
            sender_public_key (str, optional): The sender's public key.
            signature (str, optional): The digital signature of the transaction.

        Returns:
            bool: True if the transaction is successfully added,
                False otherwise.
        """
        transaction = utils.sorted_dict_by_key({
            "sender_blockchain_address" : sender_blockchain_address,
            "recipient_blockchain_address" : recipient_blockchain_address,
            "value" : float(value)
        })
        if sender_blockchain_address == MINING_SENDER:
            self.transaction_pool.append(transaction)
            return True
        
        if self.verify_transaction_signature(
            sender_public_key, signature, transaction):
            # if self.calculate_total_amount(sender_blockchain_address) < float(value):
            #     logger.error({"action": "add_transaction", "errpr": "np_value"})
            #     return False
            self.transaction_pool.append(transaction)
            return True
        return False
    
    def verify_transaction_signature(
            self, sender_public_key, signature, transaction):
        sha256 = hashlib.sha256()
        sha256.update(str(transaction).encode('utf-8'))
        message = sha256.digest()
        signature_bytes = bytes().fromhex(signature)
        verifying_key = VerifyingKey.from_string(
            bytes().fromhex(sender_public_key), curve=NIST256p)
        verifying_key = verifying_key.verify(signature_bytes, message)
        return verifying_key
    
    def valid_proof(self, transactions, previous_hash, nonce,
                    difficulty=MINING_DIFFICULTY):
        guess_block = utils.sorted_dict_by_key({
            'transactions' : transactions,
            'nonce' : nonce,
            'previous_hash' : previous_hash
        })
        guess_hash = self.hash(guess_block)
        return guess_hash[:difficulty] == '0'*difficulty
    
    def proof_of_work(self):
        transaction = self.transaction_pool.copy()
        previous_hash = self.hash(self.chain[-1])
        nonce = 0
        while self.valid_proof(transaction, previous_hash, nonce) is False:
            nonce += 1
        return nonce
    
    def mining(self):
        nonce = self.proof_of_work
        self.add_transaction(
            sender_blockchain_address=MINING_SENDER,
            recipient_blockchain_address=self.blockchain_address,
            value=MINING_REWARD
        )
        nonce = self.proof_of_work()
        previous_hash = self.hash(self.chain[-1])
        self.create_block(nonce, previous_hash)
        logger.info({'action': 'mining', 'status': 'success'})
        return True
    
    def calculate_total_amount(self, blockchain_address):
        total_amount = 0.0
        for block in self.chain:
            for transaction in block["transactions"]:
                value = float(transaction["value"])
                if blockchain_address == transaction["recipient_blockchain_address"]:
                    total_amount += value
                if blockchain_address == transaction["sender_blockchain_address"]:
                    total_amount -= value
        return total_amount
