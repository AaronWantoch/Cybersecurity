from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils, padding, rsa

class Asymmetric:
    """
    -RSA keys have a complex internal structure with specific mathematical properties.
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
        signature = private_key.sign(
            messageByteFormat,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # verification
        public_key.verify(
            signature,
            messageByteFormat,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
"""