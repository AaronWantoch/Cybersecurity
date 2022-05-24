from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils, padding, rsa
from Crypto.Cipher import AES
from tinyec import registry
import hashlib, secrets, binascii


class Asymmetric:
    #A brainpoolP256r1 named curve
    curve = registry.get_curve('brainpoolP256r1')
    """
    -RSA keys have a complex internal structure with specific mathematical properties.
    -Minimal key size 2048
    -Signing with private_key
    -Encryption with public_key
    -Decryption with private_key
    -SHA 256 algorithm, is one of the most widely used hash algorithms. While there are
     other variants, SHA 256 has been at the forefront of real-world applications
     -returns ciphertext - enctypted message, private_key -  private key generated from public key
    """

    def RSA_encrypt(self, message, key_size):
        messageByteFormat = bytes(message, 'utf-8')
        print(f"The string i want to encrypt: {messageByteFormat}.")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()

        ciphertext = public_key.encrypt(
            messageByteFormat,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext, private_key

    """
     -returns plaintext - decrypted message
    """

    def RSA_decrypt(self, ciphertext, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    """
    -The elliptic curve cryptography (ECC) does not directly provide encryption method. 
     Instead, we can design a hybrid encryption scheme by using the ECDH (Elliptic Curve Diffie–Hellman)
     key exchange scheme to derive a shared secret key for symmetric data encryption and decryption.
    """

    def encrypt_AES_GCM(self, msg, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
        return ciphertext, aesCipher.nonce, authTag

    def decrypt_AES_GCM(self, ciphertext, nonce, authTag, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext

    def ecc_point_to_256_bit_key(self, point):
        sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
        sha.update(int.to_bytes(point.y, 32, 'big'))
        return sha.digest()

    def encrypt_ECC(self, msg, pubKey):
        # function first generates an ephemeral ECC key-pair for the ciphertext
        ciphertextPrivKey = secrets.randbelow(self.curve.field.n)
        #and calculates the symmetric encryption shared ECC key
        sharedECCKey = ciphertextPrivKey * pubKey
        secretKey = self.ecc_point_to_256_bit_key(sharedECCKey)
        ciphertext, nonce, authTag = self.encrypt_AES_GCM(msg, secretKey)
        ciphertextPubKey = ciphertextPrivKey * self.curve.g
        return ciphertext, nonce, authTag, ciphertextPubKey

    def decrypt_ECC(self, encryptedMsg, privKey):
        (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
        sharedECCKey = privKey * ciphertextPubKey
        secretKey = self.ecc_point_to_256_bit_key(sharedECCKey)
        plaintext = self.decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
        return plaintext


# =============================================================

asym = Asymmetric()
msg = b'Text to be encrypted by ECC public key and ' \
      b'decrypted by its corresponding ECC private key'
print("original msg:", msg)
privKey = secrets.randbelow(asym.curve.field.n)
pubKey = privKey * asym.curve.g
encryptedMsg = asym.encrypt_ECC(msg, pubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),    # obtained by the symmetric AES-GCM encryption
    'nonce': binascii.hexlify(encryptedMsg[1]),         # random AES initialization vector
    'authTag': binascii.hexlify(encryptedMsg[2]),       # the MAC code of the encrypted text, obtained by the GCM block mode
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}
print("encrypted msg:", encryptedMsgObj)

decryptedMsg = asym.decrypt_ECC(encryptedMsg, privKey)
print("decrypted msg:", decryptedMsg)

