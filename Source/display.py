import os
import time
from utils import Utils

from symmetric import Symmetric


class Display:
    # Block must be size of multiple of 2
    @staticmethod
    def displayMessageAES(text):
        extended = Utils.extendToMultipleOf2(text)
        bytes = extended.encode("utf-8")
        key = os.urandom(32)
        initializationVector = os.urandom(16)
        baseLength = len(text)

        start = time.time()
        encrypted = Symmetric.encryptAES(bytes, key, initializationVector)
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
        print(decrypted[0:baseLength])
        print("It took ", end - start, " ms.")

