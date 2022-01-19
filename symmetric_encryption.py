from Crypto.Cipher import AES
import argparse, binascii, hashlib


class CommandLine:
    def __init__(self):

        parser = argparse.ArgumentParser(description="Description for my parser")
        parser.add_argument("-m", "--plain_text_message", help="Plaintext message to encrypt argument", required=True)
        parser.add_argument("-k", "--key", help="AES Secret Key argument", required=True)
        parser.add_argument("-iv", "--init_vector", help="Initialization Vector argument", required=False, default='925a9421613fbefb338f832db0bd1ebd')

        argument = parser.parse_args()

        init_vector = binascii.unhexlify(argument.init_vector)
        key_string = argument.key
        plaintext = argument.plain_text_message

        print('Secret Key : ', key_string)
        print('Plaintext Message : ', plaintext)
        print('Hexlified Initialization Vector : ', binascii.hexlify(init_vector))

        key = hashlib.sha256(key_string.encode()).digest()

        # First make your data a bytes object. To convert a string to a bytes object, we can call .encode() on it
        data = plaintext.encode('latin-1')

        # Create the cipher object and encrypt the data
        cipher_encrypt = AES.new(key, AES.MODE_CFB, init_vector)
        ciphered_bytes = cipher_encrypt.encrypt(data)

        print('Ciphered Data: ' + ciphered_bytes.decode('latin-1'))
        print('Hexlified Cipher Data')
        print(binascii.hexlify(ciphered_bytes))


if __name__ == "__main__":
   app = CommandLine()