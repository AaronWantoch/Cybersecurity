import os
import time

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

from utils import Utils
from asymmetric import Asymmetric
from symmetric import Symmetric
import matplotlib.pyplot as plt
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long


class Display:
    lenghts = [32, 3000, 10000, 50000, 15000000, 30000000, 450000000, 600000000, 900000000]
    # Block must be size of multiple of 2
    @staticmethod
    def drawPlotsAES():
        encryptionTimes = []
        decryptionTimes = []
        Display.generateDataAES(decryptionTimes, encryptionTimes, Display.lenghts)

        plt.title("AES speed")
        Display.drawPlots(decryptionTimes, encryptionTimes, Display.lenghts)


    @staticmethod
    def generateDataAES(decryptionTimes, encryptionTimes, lenghts):
        for i in lenghts:
            randomText = Display.getPlaintext(i)
            encryptionTime, decrytpionTime = Display.getTimeAES(randomText, 256)
            encryptionTimes.append(encryptionTime)
            decryptionTimes.append(decrytpionTime)

    @staticmethod
    def getTimeAES(text, keySize = 256):
        key = get_random_bytes(int(keySize/8))
        start = time.time()
        #print("Text to encrypt:" + text.decode("utf8"))
        encryptedText, tag, nonce = Symmetric.encryptAES(text, key)
        end = time.time()
        encryptionTime = end-start
        #print("encrypted text: " + encryptedText.decode("utf8"))
        start = time.time()
        decrypted = Symmetric.decryptAES(encryptedText, key, tag, nonce)
        end = time.time()
        decryptionTime = end-start
        #print("decrypted text: " + decrypted.decode("utf8"))

        return encryptionTime, decryptionTime

    @staticmethod
    def drawPlotsSalsa20():
        encryptionTimes = []
        decryptionTimes = []
        Display.generateDataSalsa20(decryptionTimes, encryptionTimes, Display.lenghts)

        plt.title("Salsa20 speed")
        Display.drawPlots(decryptionTimes, encryptionTimes, Display.lenghts)


    @staticmethod
    def generateDataSalsa20(decryptionTimes, encryptionTimes, lenghts):
        for i in lenghts:
            randomText = Display.getPlaintext(i)
            encryptionTime, decrytpionTime = Display.getTimeSalsa20(randomText, 256)
            encryptionTimes.append(encryptionTime)
            decryptionTimes.append(decrytpionTime)

    @staticmethod
    def getTimeSalsa20(text, keySize = 256):
        key = get_random_bytes(int(keySize/8))
        start = time.time()
        #print("Text to encrypt:" + text.decode("utf8"))
        encryptedText = Symmetric.encryptSalsa20(text, key)
        end = time.time()
        encryptionTime = end-start
        #print("encrypted text: " + encryptedText.decode("utf8"))
        start = time.time()
        decrypted = Symmetric.decryptSalsa20(encryptedText, key)
        end = time.time()
        decryptionTime = end-start
        #print("decrypted text: " + decrypted.decode("utf8"))

        return encryptionTime, decryptionTime

    @staticmethod
    def drawPlotsDES3():
        DESlenghts = [32, 15000000, 30000000, 35000000, 40000000, 60000000, 80000000, 90000000, 120000000]
        encryptionTimes = []
        decryptionTimes = []
        Display.generateDataDES3(decryptionTimes, encryptionTimes, DESlenghts)

        plt.title("DES3 speed (smaller data)")
        Display.drawPlots(decryptionTimes, encryptionTimes, DESlenghts)


    @staticmethod
    def generateDataDES3(decryptionTimes, encryptionTimes, lenghts):
        for i in lenghts:
            randomText = Display.getPlaintext(i)
            encryptionTime, decrytpionTime = Display.getTimeDES3(randomText, 24)
            encryptionTimes.append(encryptionTime)
            decryptionTimes.append(decrytpionTime)

    @staticmethod
    def getTimeDES3(text, keySize = 24):
        key = Display.get_key_DES3(keySize)

        start = time.time()
        # print("Text to encrypt:" + str(text))
        encryptedText, nonce = Symmetric.encryptDES3(text, key)
        end = time.time()
        encryptionTime = end-start
        #print("encrypted text: " + encryptedText.decode("utf8"))
        start = time.time()
        decrypted = Symmetric.decryptDES3(encryptedText, key, nonce)
        end = time.time()
        decryptionTime = end-start
        # print("decrypted text: " + str(decrypted))


        return encryptionTime, decryptionTime

    @staticmethod
    def get_key_DES3(keySize):
        while True:
            try:
                key = DES3.adjust_key_parity(get_random_bytes(keySize))
                break
            except ValueError:
                pass
        return key

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

    #RSA
    @staticmethod
    def drawPlotsRSA():
        encryptionTimes = []
        decryptionTimes = []
        Display.generateDataRSA(decryptionTimes, encryptionTimes, Display.lenghts)

        plt.title("RSA speed")
        Display.drawPlots(decryptionTimes, encryptionTimes, Display.lenghts)

    @staticmethod
    def generateDataRSA(decryptionTimes, encryptionTimes, lenghts):
        for i in lenghts:
            randomText = Display.getPlaintext(i)
            encryptionTime, decrytpionTime = Display.getTimeRSA(randomText, 256)
            encryptionTimes.append(encryptionTime)
            decryptionTimes.append(decrytpionTime)

    @staticmethod
    def getTimeRSA(text, keySize=2048):
        start = time.time()
        encryptedText, private_key = Asymmetric.encrypt_RSA(text, keySize)
        end = time.time()
        encryptionTime = end - start
        start = time.time()
        Asymmetric.decrypt_RSA(encryptedText, private_key)
        end = time.time()
        decryptionTime = end - start

        return encryptionTime, decryptionTime

    #ECC
    @staticmethod
    def drawPlotsECC():
        encryptionTimes = []
        decryptionTimes = []
        Display.generateDataECC(decryptionTimes, encryptionTimes, Display.lenghts)

        plt.title("ECC speed")
        Display.drawPlots(decryptionTimes, encryptionTimes, Display.lenghts)

    @staticmethod
    def generateDataECC(decryptionTimes, encryptionTimes, lenghts):
        for i in lenghts:
            randomText = Display.getPlaintext(i)
            encryptionTime, decrytpionTime = Display.getTimeECC(randomText, 256)
            encryptionTimes.append(encryptionTime)
            decryptionTimes.append(decrytpionTime)

    @staticmethod
    def getTimeECC(text):
        start = time.time()
        privKey, encryptedMsg = Asymmetric.encrypt_ECC(text)
        end = time.time()
        encryptionTime = end - start
        start = time.time()
        Asymmetric.decrypt_ECC(encryptedMsg, privKey)
        end = time.time()
        decryptionTime = end - start

        return encryptionTime, decryptionTime

    # ElGamal
    @staticmethod
    def drawPlotsElGamal():
        encryptionTimes = []
        decryptionTimes = []
        Display.generateDataElGamal(decryptionTimes, encryptionTimes, Display.lenghts)

        plt.title("ElGamal speed")
        Display.drawPlots(decryptionTimes, encryptionTimes, Display.lenghts)

    @staticmethod
    def generateDataElGamal(decryptionTimes, encryptionTimes, lenghts):
        for i in lenghts:
            randomText = Display.getPlaintext(i)
            encryptionTime, decrytpionTime = Display.getTimeElGamal(randomText, 256)
            encryptionTimes.append(encryptionTime)
            decryptionTimes.append(decrytpionTime)

    @staticmethod
    def getTimeElGamal(text):
        start = time.time()
        en_msg, pqkey = Asymmetric.encrypt_el_gamal(text)
        end = time.time()
        encryptionTime = end - start
        start = time.time()
        Asymmetric.decrypt_el_gamal(en_msg, pqkey)
        end = time.time()
        decryptionTime = end - start

        return encryptionTime, decryptionTime



    # Gets bytes of text
    @staticmethod
    def getPlaintext(i):
        return get_random_bytes(i)

    @staticmethod
    def drawPlots(decryptionTimes, encryptionTimes, lenghts):
        plt.plot(lenghts, encryptionTimes, marker="o", label="encryption time")
        plt.plot(lenghts, decryptionTimes, marker="o", label="decryption time")
        plt.legend()
        plt.xlabel("Length of text")
        plt.ylabel("time [s]")
        plt.grid()
        plt.show()

