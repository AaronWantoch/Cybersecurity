import os
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES, Salsa20, DES3


class Symmetric:
    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
    @staticmethod
    def encryptAES(plainText, key):
        cipher = AES.new(key, AES.MODE_EAX)
        encryptedText, tag = cipher.encrypt_and_digest(plainText)
        nonce = cipher.nonce
        return encryptedText, tag, nonce

    @staticmethod
    def decryptAES(encryptedText, key, tag, nonce):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plainText = cipher.decrypt(encryptedText)
        try:
            cipher.verify(tag)
            print("The message is authentic")
            return plainText
        except ValueError:
            print("Key incorrect or message corrupted")

    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/salsa20.html
    @staticmethod
    def encryptSalsa20(plainText, key):
        cipher = Salsa20.new(key=key)
        encryptedText = cipher.nonce + cipher.encrypt(plainText)
        return encryptedText

    @staticmethod
    def decryptSalsa20(encryptedText, key):
        nonce = encryptedText[:8]
        ciphertext = encryptedText[8:]
        cipher = Salsa20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

    @staticmethod
    def encryptDES3(plainText, key):
        cipher = DES3.new(key, DES3.MODE_EAX)
        nonce = cipher.nonce
        encryptedText = cipher.encrypt(plainText)
        return encryptedText, nonce

    @staticmethod
    def decryptDES3(encryptedText, key, nonce):
        cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(encryptedText)
        return plaintext
