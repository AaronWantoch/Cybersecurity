from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long

from ImageEncDecFunctions import *
import datetime
from csvFileManager import *

imageName = 'img_5v2'


def ECB_cipher_enc(key):
    beginTime = datetime.datetime.now()

    img_to_enc = Image.open("Images/" + imageName + ".png")
    img_encrypted = image_encrypt(img_to_enc, AES.MODE_ECB, key)
    saveImage(img_encrypted, "Images/" + imageName + "_ECB_enc.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def ECB_cipher_dec(key):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_ECB_enc.png")
    img_decrypted = image_decrypt(img_to_dec, AES.MODE_ECB, key)
    saveImage(img_decrypted, "Images/" + imageName + "_ECB_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def ECB_cipher(key):
    enc_time = ECB_cipher_enc(key)
    dec_time = ECB_cipher_dec(key)

    return enc_time, dec_time


def CBC_cipher_enc(key):
    beginTime = datetime.datetime.now()

    img_to_enc = Image.open("Images/" + imageName + ".png")
    img_encrypted = image_encrypt(img_to_enc, AES.MODE_CBC, key)
    saveImage(img_encrypted, "Images/" + imageName + "_CBC_enc.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def CBC_cipher_dec(key):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_CBC_enc.png")
    img_decrypted = image_decrypt(img_to_dec, AES.MODE_CBC, key)
    saveImage(img_decrypted, "Images/" + imageName + "_CBC_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def CBC_cipher(key):
    enc_time = CBC_cipher_enc(key)
    dec_time = CBC_cipher_dec(key)

    return enc_time, dec_time


def OFB_cipher_enc(key, init_vector):
    beginTime = datetime.datetime.now()

    img_to_enc = Image.open("Images/" + imageName + ".png")
    img_encrypted = image_encrypt_iv(img_to_enc, AES.MODE_OFB, init_vector, key)
    saveImage(img_encrypted, "Images/" + imageName + "_OFB_enc.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def OFB_cipher_dec(key, init_vector):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_OFB_enc.png")
    img_decrypted = image_decrypt_iv(img_to_dec, AES.MODE_OFB, init_vector, key)
    saveImage(img_decrypted, "Images/" + imageName + "_OFB_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def OFB_cipher(key, init_vector):
    enc_time = OFB_cipher_enc(key, init_vector)
    dec_time = OFB_cipher_dec(key, init_vector)

    return enc_time, dec_time


def CFB_cipher_enc(key, init_vector):
    beginTime = datetime.datetime.now()

    img_to_enc = Image.open("Images/" + imageName + ".png")
    img_encrypted = image_encrypt_iv(img_to_enc, AES.MODE_CFB, init_vector, key)
    saveImage(img_encrypted, "Images/" + imageName + "_CFB_enc.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def CFB_cipher_dec(key, init_vector):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_CFB_enc.png")
    img_decrypted = image_decrypt_iv(img_to_dec, AES.MODE_CFB, init_vector, key)
    saveImage(img_decrypted, "Images/" + imageName + "_CFB_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def CFB_cipher(key, init_vector):
    enc_time = CFB_cipher_enc(key, init_vector)
    dec_time = CFB_cipher_dec(key, init_vector)

    return enc_time, dec_time


def CTR_cipher_enc(key, counter):
    beginTime = datetime.datetime.now()

    img_to_enc = Image.open("Images/" + imageName + ".png")
    img_encrypted = image_encrypt_ctr(img_to_enc, AES.MODE_CTR, counter, key)
    saveImage(img_encrypted, "Images/" + imageName + "_CTR_enc.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def CTR_cipher_dec(key, counter):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_CTR_enc.png")
    img_decrypted = image_decrypt_ctr(img_to_dec, AES.MODE_CTR, counter, key)
    saveImage(img_decrypted, "Images/" + imageName + "_CTR_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = (finishTime - beginTime).total_seconds()
    return finalTime


def CTR_cipher(key, init_vector):
    counter = Counter.new(128, initial_value=bytes_to_long(init_vector))

    enc_time = CTR_cipher_enc(key, counter)
    dec_time = CTR_cipher_dec(key, counter)

    return enc_time, dec_time


def calcAllTimes():
    csvRows = []
    csvRows += calcTimeForCipherMode(ECB_cipher, "ECB")
    csvRows += calcTimeForCipherMode(CFB_cipher, "CFB")
    csvRows += calcTimeForCipherMode(OFB_cipher, "OFB")
    csvRows += calcTimeForCipherMode(CBC_cipher, "CBC")
    csvRows += calcTimeForCipherMode(CTR_cipher, "CTR")
    return csvRows


if __name__ == '__main__':
    csvFileName = "CSV/AllTimes.csv"
    csvColumnNames = ['ModeName', 'KeyLength', 'EncTime', 'DecTime']
    csvRows = calcAllTimes()
    saveCSVFileWithData(csvFileName, csvColumnNames, csvRows)
    generateEncDecPlots(csvFileName, csvColumnNames)
