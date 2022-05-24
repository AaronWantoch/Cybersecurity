from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils, padding, rsa
from Crypto.Cipher import AES
from tinyec import registry
import hashlib, secrets, binascii
import random
from math import pow


class Asymmetric:
    # A brainpoolP256r1 named curve
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
    def encrypt_RSA(self, message, key_size):
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
    def decrypt_RSA(self, ciphertext, private_key):
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

    def _encrypt_AES_GCM(self, msg, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
        return ciphertext, aesCipher.nonce, authTag

    def _decrypt_AES_GCM(self, ciphertext, nonce, authTag, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext

    def _ecc_point_to_256_bit_key(self, point):
        sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
        sha.update(int.to_bytes(point.y, 32, 'big'))
        return sha.digest()

    def encrypt_ECC(self, msg):
        messageByteFormat = bytes(msg, 'utf-8')
        privKey = secrets.randbelow(self.curve.field.n)
        pubKey = privKey * self.curve.g
        ciphertextPrivKey = secrets.randbelow(self.curve.field.n)
        sharedECCKey = ciphertextPrivKey * pubKey
        secretKey = self._ecc_point_to_256_bit_key(sharedECCKey)
        ciphertext, nonce, authTag = self._encrypt_AES_GCM(messageByteFormat, secretKey)
        ciphertextPubKey = ciphertextPrivKey * self.curve.g
        return privKey, (ciphertext, nonce, authTag, ciphertextPubKey)

    def decrypt_ECC(self, encryptedMsg, privKey):
        (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
        sharedECCKey = privKey * ciphertextPubKey
        secretKey = self._ecc_point_to_256_bit_key(sharedECCKey)
        plaintext = self._decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
        return plaintext

    '''
    ElGamal encryption is a public-key cryptosystem. It uses asymmetric key encryption for communicating 
    between two parties and encrypting the message. This cryptosystem is based on the difficulty of finding
     discrete logarithm in a cyclic group that is even if we know ga and gk, it is extremely difficult to compute g^ak.
    '''

    # Greatest common divisor
    def _gcd(self, a, b):
        if a < b:
            return self._gcd(b, a)
        elif a % b == 0:
            return b
        else:
            return self._gcd(b, a % b)

    # Generating large random numbers
    def _gen_key(self, q):
        key = random.randint(pow(10, 20), q)
        while self._gcd(q, key) != 1:
            key = random.randint(pow(10, 20), q)

        return key

    # Modular exponentiation
    def _power(self, a, b, c):
        x = 1
        y = a

        while b > 0:
            if b % 2 != 0:
                x = (x * y) % c
            y = (y * y) % c
            b = int(b / 2)

        return x % c

    # Asymmetric encryption
    def encrypt_el_gamal(self, msg):

        q = random.randint(pow(10, 20), pow(10, 50))
        g = random.randint(2, q)

        key = self._gen_key(q)  # Private key for receiver
        h = self._power(g, key, q)
        en_msg = []

        k = self._gen_key(q)  # Private key for sender
        s = self._power(h, k, q)
        p = self._power(g, k, q)

        for i in range(0, len(msg)):
            en_msg.append(msg[i])

        print("g^ak used : ", s)
        for i in range(0, len(en_msg)):
            en_msg[i] = s * ord(en_msg[i])

        return en_msg, (p, q, key)

    def decrypt_el_gamal(self, en_msg, pqkey):
        dr_msg = []
        h = self._power(pqkey[0], pqkey[2], pqkey[1])
        for i in range(0, len(en_msg)):
            dr_msg.append(chr(int(en_msg[i] / h)))

        return dr_msg

'''''
asym = Asymmetric()
''''''
msg = 'Text to be encrypted by RSA'
print("Original Message :", msg)
ciphertext, private_key = asym.encrypt_RSA(msg, 2048)
print("encrypted msg:", ciphertext)
decrypted = asym.decrypt_RSA(ciphertext,private_key)
print("decrypted msg:", decrypted)
''''''
msg = 'encryption'
print("Original Message :", msg)
# Bob chooses a very large number q and a cyclic group Fq.
en_msg, pqkey = asym.encrypt_el_gamal(msg)
dr_msg = asym.decrypt_el_gamal(en_msg, pqkey)
dmsg = ''.join(dr_msg)
print("Decrypted Message :", dmsg);
''''''
msg = 'Text to be encrypted by ECC public key and ' \
      'decrypted by its corresponding ECC private key'
print("original msg:", msg)
privKey, encryptedMsg = asym.encrypt_ECC(msg)
print("encrypted msg:", encryptedMsg[0])
decryptedMsg = asym.decrypt_ECC(encryptedMsg, privKey)
print("decrypted msg:", decryptedMsg)
'''