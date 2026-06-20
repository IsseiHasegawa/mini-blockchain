import hashlib
import json
import logging 
import sys
import time

import utils

logging.basicConfig(level=logging.INFO, stream=sys.stdout)

class BlockChain():
    
    def __init__(self):
        self.transaction_pool = []
        self.chain = []
        self.create_chain(0, self.hash({}))
    
    def create_chain(self, nonce, previous_hash):
        block = utils.sorted_dict_by_key({
            "timestamp": time.time(),
            "transaction_pool": self.transaction_pool,
            "nonce": nonce,
            "previous_hash": previous_hash
        })

        self.chain.append(block)
        self.transaction_pool = []
        return block
    
    def hash(self, block:dict):
        sorted_block = json.dumps(block, sort_keys=True)
        return hashlib.sha256(sorted_block.encode()).hexdigest()
    
def pprint(chains: list):
    for i, block in enumerate(chains):
        print(f"{'='*25} Chain {i} {'='*25}")
        for k, v in block.items():
            print(f"{k:15} {v}")
    print(f"{'*'*25}")



if __name__ == "__main__":
    block_chain = BlockChain()
    pprint(block_chain.chain)

    previous_hash = block_chain.hash(block_chain.chain[-1])
    block_chain.create_chain(5, previous_hash)
    pprint(block_chain.chain)

    previous_hash = block_chain.hash(block_chain.chain[-1])
    block_chain.create_chain(2, previous_hash)
    pprint(block_chain.chain)


