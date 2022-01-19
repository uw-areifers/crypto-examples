from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import argparse


class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Description for my parser")
        parser.add_argument("-if", "--input_file", help="Output File Name argument", required=True, default="")
        parser.add_argument("-pk", "--private_key", help="Plaintext Message argument", required=False, default='bobs_private_key.pem')

        argument = parser.parse_args()
        encrypted_file_name = argument.input_file
        private_key_file_name = argument.private_key

        file_in = open(encrypted_file_name, "rb")

        private_key = RSA.import_key(open(private_key_file_name).read())

        enc_session_key, nonce, tag, ciphertext = \
           [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print(data.decode("utf-8"))


if __name__ == "__main__":
   app = CommandLine()