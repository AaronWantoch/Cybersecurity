import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Symmetric:
    #Link to article: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#symmetric-encryption-modes
    @staticmethod
    def encryptAES(plainText, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encryptedText = encryptor.update(plainText) + encryptor.finalize()
        return encryptedText

    @staticmethod
    def decryptAES(encryptedText, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decryptedText = decryptor.update(encryptedText) + decryptor.finalize()
        return decryptedText
