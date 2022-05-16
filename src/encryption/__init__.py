import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Encryption:
    def __init__(self):
        self.BLOCK_SIZE_BITS = 128
        self.BLOCK_SIZE_BYTES = 16

        self.key = os.urandom(self.BLOCK_SIZE_BYTES)
        self.iv = os.urandom(self.BLOCK_SIZE_BYTES)

        # Use OFB so we don't need padding
        self.cipher = Cipher(algorithm=algorithms.AES(self.key), mode=modes.OFB(self.iv))

        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def encrypt_internal(self, text):
        return self.encryptor.update(text)

    def encrypt_finalize_internal(self):
        return self.encryptor.finalize()

    def encrypt(self, file_path):
        # Read file as bytes
        ciphertext = []
        with open(file_path, 'rb') as fd:
            line = fd.read(self.BLOCK_SIZE_BYTES)
            while line:
                ciphertext.append(self.encrypt_internal(line))
                line = fd.read(self.BLOCK_SIZE_BYTES)

        ciphertext.append(self.encrypt_finalize_internal())

        # Join byte array
        return b''.join(ciphertext)

    def decrypt_internal(self, ciphertext):
        return self.decryptor.update(ciphertext)

    def decrypt_finalize_internal(self):
        return self.decryptor.finalize()

    def decrypt(self, ciphertext):
        plaintext = []

        for c in ciphertext:
            plaintext.append(self.decrypt_internal(c))

        final = self.decrypt_finalize_internal()
        if final:
            plaintext.append(final)
        return plaintext

    def run(self, file_path):
        ciphertext = self.encrypt(file_path)
        plaintext = self.decrypt(ciphertext)
        return plaintext
