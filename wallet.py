import base58
import hashlib
import codecs
import binascii

from ecdsa import NIST256p
from ecdsa import SigningKey

class Wallet():

    def __init__(self):
        self._private_key = SigningKey.generate(NIST256p)
        self._public_key = self._private_key.get_verifying_key()

    @property
    def private_key(self):
        return self._private_key.to_string().hex()
    
    @property
    def public_key(self):
        return self._public_key.to_string().hex()
    
    def generate_blockchain_address(self):
        #  1 SHA-256 for the public key
        public_key_bytes = self.public_key.to_string()
        sha256_bpk = hashlib.sha256(self.public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()

        # 2 Ripemd260 for the SHA-256
        ripemd160_bpk = hashlib.new("ripemd160")
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, "hex")

        # 3 ADD newtwork byte
        network_byte = b"00"
        newtwork_bitocoin_public_key = network_byte + ripemd160_bpk_hex
        newtwork_bitocoin_public_key_bytes = codecs.decode(newtwork_bitocoin_public_key, "hex")

        # 4 Double SHA-256
        sha256_bpk = hashlib.sha256(newtwork_bitocoin_public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_bpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_hex = codecs.encode(sha256_2_nbpk_digest, "hex")
    
        # 5 Get checksum
        checksum = sha256_hex[:8]

        # 6 Concatenate public key and checksum
        address_hex = (newtwork_bitocoin_public_key + checksum).decode("utf-8")

        # 7 Encoding the key with Base 58
        blockchain_address = base58.b58decode(binascii.unhexlify(address_hex)).decode("utf-8")

        return blockchain_address

    

if __name__ == "__main__":
    wallet = Wallet()
    print(wallet.private_key)
    print(wallet.public_key)
        