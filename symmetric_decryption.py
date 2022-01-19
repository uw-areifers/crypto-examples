from Crypto.Cipher import AES
import argparse, binascii, hashlib


class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Description for my parser")
        parser.add_argument("-c", "--cipher", help="Cipher Data argument", required=True, default="")
        parser.add_argument("-k", "--key", help="AES Secret Key argument", required=True, default="")
        parser.add_argument("-iv", "--init_vector", help="Initialization Vector argument", required=False, default='925a9421613fbefb338f832db0bd1ebd')

        argument = parser.parse_args()
        init_vector = binascii.unhexlify(argument.init_vector)
        cipher_data = binascii.unhexlify(argument.cipher)
        secret_key = argument.key

        print('Secret Key : ', secret_key)
        print('Hexlified Initialization Vector : ', binascii.hexlify(init_vector))
        print('Cipher Data : ')
        print(cipher_data.decode('latin-1'))
        print('Hexlified Cipher Data : ', binascii.hexlify(cipher_data))

        key = hashlib.sha256(secret_key.encode()).digest()

        cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=init_vector)
        deciphered_bytes = cipher_decrypt.decrypt(cipher_data)

        decrypted_data = deciphered_bytes.decode('latin-1')
        print('Decrypted Data: ' + decrypted_data)


if __name__ == "__main__":
   app = CommandLine()

