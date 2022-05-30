from display import Display
from utils import Utils
from symmetric import Symmetric

if __name__ == '__main__':
    Display.drawPlotsDES3()
    Display.drawPlotsSalsa20()
    Display.drawPlotsAES()

    plaintext = "This is the text to encode"
    key = "This is 16 B key"

    print("Text to encode: ", plaintext)
    print("key: ", plaintext)
    encoded, tag, nonce = Symmetric.encryptAES(plaintext.encode("utf-8"), key.encode("utf-8"))
    print("Ciphertext: ", encoded)
    decoded = Symmetric.decryptAES(encoded, key.encode("utf-8"), tag, nonce)
    print("Decoded: ", decoded.decode("utf-8"))
