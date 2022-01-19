from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import argparse, binascii


class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Description for my parser")
        parser.add_argument("-s", "--signature", help="Signature Data argument", required=True)
        parser.add_argument("-m", "--message", help="Message Data argument", required=True)
        parser.add_argument("-k", "--public_key_file", help="Public key argument", required=False, default='alices_public_key.pem')

        argument = parser.parse_args()
        signature = binascii.unhexlify(argument.signature)
        public_key = RSA.import_key(open(argument.public_key_file).read())

        # Verify valid PKCS#1 v1.5 signature (RSAVP1)
        msg = argument.message.encode()
        hash_message = SHA256.new(msg)
        print("Hexlified Signature:", binascii.hexlify(signature))
        print('Message:', msg)
        verifier = PKCS115_SigScheme(public_key)
        try:
            verifier.verify(hash_message, signature)
            print("Signature is valid.")
        except:
            print("Signature is invalid.")


if __name__ == "__main__":
    app = CommandLine()