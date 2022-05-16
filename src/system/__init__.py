from cryptography.hazmat.primitives import hashes
from ..encryption import *
from ..mac import *


class System:
    def __init__(self):
        self.encryption = Encryption()
        self.mac = Mac()
        # The set to hold valid messages in order to prevent replay attack
        self.sent = set()

    def encrypt(self, file_path):
        # Encrypt-then-Mac
        ciphertext = self.encryption.encrypt(file_path)
        tag = self.mac.generate_tag(ciphertext)
        # Add the hash of the tag to the holding set
        self.sent.add(self.getSha(tag))

        return ciphertext, tag

    def verify(self, tag):
        # Verify that this message is indeed sent and not seen yet to prevent replay attack
        # If the tag is modified, it is also not in the set
        seq = self.getSha(tag)
        if seq not in self.sent:
            raise ValueError(f'This message is already processed or it is not a valid tag.')

        self.sent.remove(seq)

        # Verify
        return self.mac.verify(tag)

    def getSha(self, tag):
        # Compute a seq number using SHA256
        digest = hashes.Hash(hashes.SHA256())
        digest.update(tag)
        return digest.finalize()
