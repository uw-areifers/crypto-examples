from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256

import hashlib, binascii, argparse


class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Description for my parser")        
        parser.add_argument("-m", "--message", help="Message to hash argument", required=True)
        parser.add_argument("-pk", "--private_key_file", help="Private key file argument", required=False,
                            default='alices_private_key.pem')

        argument = parser.parse_args()
        message_to_hash_and_sign = argument.message

        private_key = RSA.import_key(open(argument.private_key_file).read())
        
        msg = message_to_hash_and_sign.encode()
        hash_message = SHA256.new(msg)

        # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
        signer = PKCS115_SigScheme(private_key)
        signature = signer.sign(hash_message)
        print('Message: ', msg)
        print("Hexlified Signature: ", binascii.hexlify(signature))


if __name__ == "__main__":
    app = CommandLine()