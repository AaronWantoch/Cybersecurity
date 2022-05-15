import PIL.Image as Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long

"""
Use only .png files

"""


def image_encrypt(img, mode, key):
    bImg = img.tobytes()
    cipher = AES.new(key, mode)
    m = cipher.encrypt(bImg)
    enc_img = Image.frombytes('RGBA', img.size, m, 'raw')
    return enc_img


def image_encrypt_iv(img, mode, iv, key):
    bImg = img.tobytes()
    cipher = AES.new(key, mode, iv)
    m = cipher.encrypt(bImg)
    enc_img = Image.frombytes('RGBA', img.size, m, 'raw')
    return enc_img


def image_encrypt_ctr(img, mode, ctr, key):
    bImg = img.tobytes()
    cipher = AES.new(key, mode, counter=ctr)
    m = cipher.encrypt(bImg)
    enc_img = Image.frombytes('RGBA', img.size, m, 'raw')
    return enc_img


def image_decrypt(enc_img, mode, key):
    bImg = enc_img.tobytes()
    cipher = AES.new(key, mode)
    m = cipher.decrypt(bImg)
    dec_img = Image.frombytes('RGBA', enc_img.size, m, 'raw')
    return dec_img


def image_decrypt_iv(enc_img, mode, iv, key):
    bImg = enc_img.tobytes()
    cipher = AES.new(key, mode, iv)
    m = cipher.decrypt(bImg)
    dec_img = Image.frombytes('RGBA', enc_img.size, m, 'raw')
    return dec_img


def image_decrypt_ctr(enc_img, mode, ctr, key):
    bImg = enc_img.tobytes()
    cipher = AES.new(key, mode, counter=ctr)
    m = cipher.decrypt(bImg)
    dec_img = Image.frombytes('RGBA', enc_img.size, m, 'raw')
    return dec_img


def saveImage(image, path):
    image.save(path, "PNG")
    # image.show() # uncomment to display image