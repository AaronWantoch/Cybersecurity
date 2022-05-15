from ImageEncDecFunctions import *
import datetime
import csv

imageName = 'img_5v2'

def ECB_cipher_enc(key):
    beginTime = datetime.datetime.now()

    img_to_enc = Image.open("Images/" + imageName + ".png")
    img_encrypted = image_encrypt(img_to_enc, AES.MODE_ECB, key)
    saveImage(img_encrypted, "Images/" + imageName + "_ECB_enc.png")

    finishTime = datetime.datetime.now()
    finalTime = finishTime - beginTime
    return finalTime


def ECB_cipher_dec(key):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_ECB_enc.png")
    img_decrypted = image_decrypt(img_to_dec, AES.MODE_ECB, key)
    saveImage(img_decrypted, "Images/" + imageName + "_ECB_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = finishTime - beginTime
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
    finalTime = finishTime - beginTime
    return finalTime


def CBC_cipher_dec(key):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_CBC_enc.png")
    img_decrypted = image_decrypt(img_to_dec, AES.MODE_CBC, key)
    saveImage(img_decrypted, "Images/" + imageName + "_CBC_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = finishTime - beginTime
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
    finalTime = finishTime - beginTime
    return finalTime


def OFB_cipher_dec(key, init_vector):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_OFB_enc.png")
    img_decrypted = image_decrypt_iv(img_to_dec, AES.MODE_OFB, init_vector, key)
    saveImage(img_decrypted, "Images/" + imageName + "_OFB_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = finishTime - beginTime
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
    finalTime = finishTime - beginTime
    return finalTime


def CFB_cipher_dec(key, init_vector):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_CFB_enc.png")
    img_decrypted = image_decrypt_iv(img_to_dec, AES.MODE_CFB, init_vector, key)
    saveImage(img_decrypted, "Images/" + imageName + "_CFB_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = finishTime - beginTime
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
    finalTime = finishTime - beginTime
    return finalTime


def CTR_cipher_dec(key, counter):
    beginTime = datetime.datetime.now()

    img_to_dec = Image.open("Images/" + imageName + "_CTR_enc.png")
    img_decrypted = image_decrypt_ctr(img_to_dec, AES.MODE_CTR, counter, key)
    saveImage(img_decrypted, "Images/" + imageName + "_CTR_dec.png")

    finishTime = datetime.datetime.now()
    finalTime = finishTime - beginTime
    return finalTime


def CTR_cipher(key, init_vector):
    counter = Counter.new(128, initial_value=bytes_to_long(init_vector))

    enc_time = CTR_cipher_enc(key, counter)
    dec_time = CTR_cipher_dec(key, counter)

    return enc_time, dec_time


def saveCSVFileWithData(csvColumnNames, csvRows):
    filename = "CSV/AllTimes.csv"
    # writing to csv file
    with open(filename, 'w') as csvfile:
        # creating a csv writer object
        csvwriter = csv.writer(csvfile)
        # writing the fields
        csvwriter.writerow(csvColumnNames)
        # writing the data rows
        csvwriter.writerows(csvRows)


def calcTimeForCipherMode(func, modeName):
    # initializing the rows list
    csvRows = []

    print("ModeName: " + modeName)
    for i in range(16, 32 + 1, 8):
        print("KeyLength:", i)
        key = get_random_bytes(i)  # value must be 16 bytes(128 bits), 24 bytes (192 bits) or 32 bytes (256 bits)
        init_vector = get_random_bytes(16)

        if(modeName in ["CFB", "CTR", "OFB"]):
            enc_time, dec_time = func(key, init_vector)
        else:
            enc_time, dec_time = func(key)

        csvRows.append([modeName, str(i), str(enc_time), str(dec_time)])  # save to main CSV array

    print('\n')
    return csvRows


if __name__ == '__main__':
    csvColumnNames = ['ModeName', 'KeyLength', 'EncTime', 'DecTime']
    csvRows = []
    csvRows += calcTimeForCipherMode(ECB_cipher, "ECB")
    csvRows += calcTimeForCipherMode(CFB_cipher, "CFB")
    csvRows += calcTimeForCipherMode(OFB_cipher, "OFB")
    csvRows += calcTimeForCipherMode(CBC_cipher, "CBC")
    csvRows += calcTimeForCipherMode(CTR_cipher, "CTR")

    saveCSVFileWithData(csvColumnNames, csvRows)

    # CFB_cipher(key, init_vector)
    # CBC_cipher(key)
    # CTR_cipher(key, init_vector)
