import os
import time

from symmetric import Symmetric


class Display:
    # Block must be size of multiple of 2
    @staticmethod
    def displayMessageAES(text):
        key = os.urandom(32)
        initializationVector = os.urandom(16)

        start = time.time()
        encrypted = Symmetric.encryptAES(text, key, initializationVector)
        end = time.time()
        print("AES encrypted message: ")
        print(text)
        print("The encrypted message is: ")
        print(encrypted)
        print("It took ", end-start, " ms.")

        start = time.time()
        decrypted = Symmetric.decryptAES(encrypted, key, initializationVector)
        end = time.time()
        print("AES decrypted message: ")
        print(encrypted)
        print("The decrypted message is: ")
        print(decrypted)
        print("It took ", end - start, " ms.")

