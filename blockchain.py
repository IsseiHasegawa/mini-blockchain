import hashlib
import json
import logging 
import sys
import time

import utils

MINING_DIFFICULTY = 3
MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1.0

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

class BlockChain():
    
    def __init__(self, blockchain_address=None):
        self.transaction_pool = []
        self.chain = []
        self.create_chain(0, self.hash({}))
        self.blockchain_address = blockchain_address
    
    def create_chain(self, nonce, previous_hash):
        block = utils.sorted_dict_by_key({
            "timestamp": time.time(),
            "transactions": self.transaction_pool,
            "nonce": nonce,
            "previous_hash": previous_hash
        })

        self.chain.append(block)
        self.transaction_pool = []
        return block
    
    def hash(self, block:dict):
        sorted_block = json.dumps(block, sort_keys=True)
        return hashlib.sha256(sorted_block.encode()).hexdigest()
    
    def add_transaction(self, sender_blockchain_address,
                        recipient_blockchain_address, value):
        transaction = utils.sorted_dict_by_key({
            "sender_blockchain_address": sender_blockchain_address,
            "recipient_blockchin_address": recipient_blockchain_address,
            "value": float(value)
        })
        self.transaction_pool.append(transaction)
        return transaction
    
    def valid_proof(self, transactions, previous_hash, nonce,
                    min_difficulty=MINING_DIFFICULTY):
        guess_block = utils.sorted_dict_by_key({
            "transactions": transactions,
            "previous_hash": previous_hash,
            "nonce": nonce
        })

        guess_hash = self.hash(guess_block)
        return guess_hash[:min_difficulty] == "0"*min_difficulty
    
    def proof_of_work(self):
        transactions = self.transaction_pool.copy()
        previous_hash = self.hash(self.chain[-1])
        nonce = 0
        while self.valid_proof(transactions, previous_hash, nonce) is False:
            nonce += 1
        return nonce

    def mining(self):
        self.add_transaction(
            sender_blockchain_address=MINING_SENDER,
            recipient_blockchain_address=self.blockchain_address,
            value=MINING_REWARD
        )
        nonce = self.proof_of_work()
        previous_hash = self.hash(self.chain[-1])
        self.create_chain(nonce, previous_hash)
        logger.info({"action": "mining", "status": "success"})
        return True
    




if __name__ == "__main__":
    my_blockchain_address = "my_blockchain_address"
    block_chain = BlockChain(blockchain_address = "my_blockchain_address")
    utils.pprint(block_chain.chain)

    block_chain.add_transaction("A", "B", 1.0)
    block_chain.mining()
    utils.pprint(block_chain.chain)

    block_chain.add_transaction("C", "D", 2.0)
    block_chain.add_transaction("X", "Y", 3.0)
    block_chain.mining()
    utils.pprint(block_chain.chain)
