from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import argparse


class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Description for my parser")
        parser.add_argument("-of", "--output_file", help="Output File Name argument", required=True, default="")
        parser.add_argument("-pt", "--plaintext", help="Plaintext Message argument", required=False, default='This is some extremely sensitive data, do not share with Reifers.')
        parser.add_argument("-k", "--public_key", help="Public key file argument", required=False, default='alices_public_key.pem')

        argument = parser.parse_args()
        plaintext_message = argument.plaintext
        output_file_name = argument.output_file
        public_key_file = argument.public_key

        print('Original Plaintext Message : ' + plaintext_message)
        print('Public Key File : ' + public_key_file)
        print('Writing Asymmetric Encrypted Data to File : ' + output_file_name)

        data = plaintext_message.encode("utf-8")
        file_out = open(output_file_name, "wb")

        recipient_key = RSA.import_key(open(public_key_file).read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
        file_out.close()

        file_in = open(output_file_name, "rb")
        print('RSA created ciphertext : ')
        print(file_in.read().decode('latin-1'))


if __name__ == "__main__":
   app = CommandLine()