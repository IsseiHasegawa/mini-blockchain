import hashlib
import json
import logging
import sys
import time
import utils

logging.basicConfig(level=logging.INFO, stream=sys.stdout)

class BlackChain(object):
    def __init__(self):
        self.transaction_pool = []
        self.chain = []
        self.create_block(0, self.hash({}))

    def create_block(self, nonce, previous_hash):
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
        sorted_block = json.dumps(block, sort_keys=True)
        return hashlib.sha256(sorted_block.encode()).hexdigest()
    
    def add_transaction(self, sender_blockchain_address,
                        recipient_blockchain_address, value):
        transaction = utils.sorted_dict_by_key({
            "sender_blockchain_address" : sender_blockchain_address,
            "recipient_blockchain_address" : recipient_blockchain_address,
            "value" : float(value)
        })
        self.transaction_pool.append(transaction)
        return True
    
def pprint(chains):
        for i, chain in enumerate(chains):
            print(f'{"="*25} Chain{i} {"="*25}')
            for k, v in chain.items():
                print(f'{k:15}{v}')
            print(f'{"*"*25}')


if __name__ == '__main__':
    block_chain = BlackChain()
    pprint(block_chain.chain)

    block_chain.add_transaction('A', 'B', 1.0)
    previous_hash = block_chain.hash(block_chain.chain[-1])
    block_chain.create_block(5, previous_hash)
    pprint(block_chain.chain)
    
    block_chain.add_transaction('C', 'D', 1.0)
    block_chain.add_transaction('X', 'Y', 1.0)
    previous_hash = block_chain.hash(block_chain.chain[-1])
    block_chain.create_block(2, previous_hash)
    pprint(block_chain.chain)
