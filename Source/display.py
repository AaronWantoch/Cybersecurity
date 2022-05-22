import os
import time
from utils import Utils
from asymmetric import Asymmetric
from symmetric import Symmetric
import matplotlib.pyplot as plt

class Display:
    # Block must be size of multiple of 2
    @staticmethod
    def drawPlotsAES():
        #To setup everything
        randomText = Utils.randomString(10)
        Display.displayMessageAES(randomText, 256)

        lenghts = [10000, 3000, 50000, 8000, 1000000, 2000000, 3000000]
        encryptionTimes = []
        decryptionTimes = []
        for i in lenghts:
            randomText = Utils.randomString(i)
            encryptionTime, decrytpionTime = Display.displayMessageAES(randomText, 256)
            encryptionTimes.append(encryptionTime)
            decryptionTimes.append(decrytpionTime)
        plt.plot(lenghts, encryptionTimes, marker="o")
        plt.plot(lenghts, decryptionTimes, marker="o")
        plt.show()


    @staticmethod
    def displayMessageAES(text, keySize = 256):
        extended = Utils.extendToMultipleOf2(text) #expands text to multiple of 2
        bytes = extended.encode("utf-8")
        key = os.urandom(int(keySize/8))
        initializationVector = os.urandom(16) #16 bytes
        baseLength = len(text)

        start = time.time()
        encrypted = Symmetric.encryptAES(bytes, key, initializationVector)
        end = time.time()
        encryptionTime = end-start

        start = time.time()
        decrypted = Symmetric.decryptAES(encrypted, key, initializationVector)
        end = time.time()
        decryptionTime = end-start

        return encryptionTime, decryptionTime

    @staticmethod
    def displayMessageRSA(message, key_size):
        start = time.time()
        encrypted, private_key = Asymmetric.RSA_encrypt(message, key_size)
        end = time.time()
        print("AES encrypted message: ")
        print(message)
        print("It took ", end - start, " s.")

        start = time.time()
        decrypted = Asymmetric.RSA_decrypt(encrypted, private_key)
        end = time.time()
        print("AES decrypted message. Decrypted message is: ")
        print(decrypted)
        print("It took ", end - start, " s.")

