from ecdsa import NIST256p
from ecdsa import SigningKey

class Wallet(object):
    def __init__(self):
        self._private_key = SigningKey.generate(curve=NIST256p)
        self._public_key = self._private_key.get_verifying_key()

    @property
    def private_key(self):
        return self._private_key.to_string().hex()
    
    @property
    def public_key(self):
        return self._public_key.to_string().hex()

if __name__ == '__main__':
    wallet = Wallet()
    print(wallet.private_key)
    print(wallet.public_key)
    

