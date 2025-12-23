import base58
import codecs
import hashlib
import utils

from ecdsa import NIST256p
from ecdsa import SigningKey

class Wallet(object):
    def __init__(self):
        self._private_key = SigningKey.generate(curve=NIST256p)
        self._public_key = self._private_key.get_verifying_key()
        self._blockchain_address = self.generate_blockchain_address()

    @property
    def private_key(self):
        return self._private_key.to_string().hex()
    
    @property
    def public_key(self):
        return self._public_key.to_string().hex()
    
    @property
    def blockchain_address(self):
        return self._blockchain_address
    
    def generate_blockchain_address(self):
        #2
        public_key_bytes = self._private_key.to_string()
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digit = sha256_bpk.digest()

        #3
        ripemed160_bpk = hashlib.new("ripemd160")
        ripemed160_bpk.update(sha256_bpk_digit)
        ripemed160_bpk_digit = ripemed160_bpk.digest()
        ripemed160_bpk_hex = codecs.encode(ripemed160_bpk_digit, "hex")

        #4
        nework_byte = b'00'
        nework_bitocoin_public_key = nework_byte + ripemed160_bpk_hex
        nework_bitocoin_public_key_byte = codecs.decode(
            nework_bitocoin_public_key, "hex"
        )

        #5 
        sha256_bpk = hashlib.sha256(nework_bitocoin_public_key_byte)
        sha256_bpk_digit = sha256_bpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_bpk_digit)
        sha256_2_bpk_digit = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_bpk_digit, "hex")

        #6 
        chechsum = sha256_2_hex[:8]

        #7 
        address_hex = (nework_bitocoin_public_key + chechsum).decode('utf-8')

        #8 
        blockchain_address = base58.b58encode(address_hex).decode('utf-8')
        return blockchain_address
    
class Transaction(object):
    def __init__(self, sender_private_key, sender_public_key,
                 sender_blockchain_address, recipient_blockchain_address,
                 value):
        self.sender_private_key = sender_private_key
        self.sender_public_key = sender_public_key
        self.sender_blockchain_address = sender_blockchain_address
        self.recipient_blockchain_address = recipient_blockchain_address
        self.value = value

    def generate_signature(self):
        sha256 = hashlib.sha256()
        transaction = utils.sorted_dict_by_key({
            "sender_blockchain_address" : self.sender_blockchain_address,
            "recipient_blockchain_address" : self.recipient_blockchain_address,
            "value" : float(self.value)
        })
        sha256.update(str(transaction).encode('utf-8'))
        message = sha256.digest()
        private_key = SigningKey.from_string(
            bytes().fromhex(self.sender_private_key), curve=NIST256p
        )
        private_key_sign = private_key.sign(message)
        signature = private_key_sign.hex()
        return signature


        

if __name__ == '__main__':
    wallet = Wallet()
    print(wallet.private_key)
    print(wallet.public_key)
    print(wallet.blockchain_address)
    t = Transaction(
        wallet.private_key, wallet.public_key, wallet.blockchain_address,
        'B', 1.0
    )
    print(t.generate_signature())
    

