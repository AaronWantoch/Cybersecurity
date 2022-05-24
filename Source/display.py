import os
import time
from utils import Utils
from asymmetric import Asymmetric

from symmetric import Symmetric


class Display:
    # Block must be size of multiple of 2
    @staticmethod
    def displayMessageAES(text, keySize = 32):
        extended = Utils.extendToMultipleOf2(text) #expands text to multiple of 2
        bytes = extended.encode("utf-8")
        key = os.urandom(keySize)
        initializationVector = os.urandom(16)
        baseLength = len(text)

        start = time.time()
        encrypted = Symmetric.encryptAES(bytes, key, initializationVector)
        end = time.time()
        print("AES encrypted message: ")
        # print(text)
        print("It took ", end-start, " s.")

        start = time.time()
        decrypted = Symmetric.decryptAES(encrypted, key, initializationVector)
        end = time.time()
        print("AES decrypted message decrypted message is: ")
        # print(decrypted[0:baseLength])
        print("It took ", end - start, " s.")

    @staticmethod
    def displayMessageRSA(message, key_size):
        start = time.time()
        encrypted, private_key = Asymmetric.encrypt_RSA(message, key_size)
        end = time.time()
        print("AES encrypted message: ")
        print(message)
        print("It took ", end - start, " s.")

        start = time.time()
        decrypted = Asymmetric.decrypt_RSA(encrypted, private_key)
        end = time.time()
        print("AES decrypted message. Decrypted message is: ")
        print(decrypted)
        print("It took ", end - start, " s.")

