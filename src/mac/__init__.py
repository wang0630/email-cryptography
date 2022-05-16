import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature


class Mac:
    def __init__(self):
        self.BLOCK_SIZE_BITS = 256
        self.key = os.urandom(self.BLOCK_SIZE_BITS // 8)
        self.digest = hmac.HMAC(self.key, hashes.SHA256())

    def generate_tag(self, ciphertext):
        self.digest.update(ciphertext)
        # Make a copy so we can perform verify() later
        copy = self.digest.copy()
        result = self.digest.finalize()
        self.digest = copy
        return result

    def verify(self, tag):
        try:
            self.digest.verify(tag)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            raise e
