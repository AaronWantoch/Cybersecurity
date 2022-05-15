from ImageEncDecFunctions import *
import datetime

def ECB_cipher_enc(key):
    img_to_enc = Image.open('Images/img_2.png')
    img_encrypted = image_encrypt(img_to_enc, AES.MODE_ECB, key)
    saveImage(img_encrypted, "Images/img_2_ECB_enc.png")


def ECB_cipher_dec(key):
    img_to_dec = Image.open('Images/img_2_ECB_enc.png')
    img_decrypted = image_decrypt(img_to_dec, AES.MODE_ECB, key)
    saveImage(img_decrypted, "Images/img_2_ECB_dec.png")


def ECB_cipher(key):
    ECB_cipher_enc(key)
    ECB_cipher_dec(key)


def CBC_cipher_enc(key):
    img_to_enc = Image.open('Images/img_2.png')
    img_encrypted = image_encrypt(img_to_enc, AES.MODE_CBC, key)
    saveImage(img_encrypted, "Images/img_2_CBC_enc.png")


def CBC_cipher_dec(key):
    img_to_dec = Image.open('Images/img_2_CBC_enc.png')
    img_decrypted = image_decrypt(img_to_dec, AES.MODE_CBC, key)
    saveImage(img_decrypted, "Images/img_2_CBC_dec.png")


def CBC_cipher(key):
    CBC_cipher_enc(key)
    CBC_cipher_dec(key)


def CFB_cipher_enc(key, init_vector):
    img_to_enc = Image.open('Images/img_2.png')
    img_encrypted = image_encrypt_iv(img_to_enc, AES.MODE_CFB, init_vector, key)
    saveImage(img_encrypted, "Images/img_2_CFB_enc.png")


def CFB_cipher_dec(key, init_vector):
    img_to_dec = Image.open('Images/img_2_CFB_enc.png')
    img_decrypted = image_decrypt_iv(img_to_dec, AES.MODE_CFB, init_vector, key)
    saveImage(img_decrypted, "Images/img_2_CFB_dec.png")


def CFB_cipher(key, init_vector):
    CFB_cipher_enc(key, init_vector)
    CFB_cipher_dec(key, init_vector)


def CTR_cipher_enc(key, counter):
    img_to_enc = Image.open('Images/img_2.png')
    img_encrypted = image_encrypt_ctr(img_to_enc, AES.MODE_CTR, counter, key)
    saveImage(img_encrypted, "Images/img_2_CTR_enc.png")


def CTR_cipher_dec(key, counter):
    img_to_dec = Image.open('Images/img_2_CTR_enc.png')
    img_decrypted = image_decrypt_ctr(img_to_dec, AES.MODE_CTR, counter, key)
    saveImage(img_decrypted, "Images/img_2_CTR_dec.png")


def CTR_cipher(key, init_vector):
    counter = Counter.new(128, initial_value=bytes_to_long(init_vector))
    CTR_cipher_enc(key, counter)
    CTR_cipher_dec(key, counter)


if __name__ == '__main__':
    key = get_random_bytes(16)  # value must be 16 bytes(128 bits), 24 bytes (192 bits) or 32 bytes (256 bits)
    init_vector = get_random_bytes(16)

    ECB_cipher(key)
    CFB_cipher(key, init_vector)
    CBC_cipher(key)
    CTR_cipher(key, init_vector)
