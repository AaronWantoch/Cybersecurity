from asymmetric import Asymmetric
a = Asymmetric()

message = "encrypted data"
a.RSA_encrypt(message, 2048)
