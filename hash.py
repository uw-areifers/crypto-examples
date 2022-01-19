from Crypto.Hash import SHA256
from Crypto.Hash import keccak
import hashlib, binascii, argparse


class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Description for my parser")        
        parser.add_argument("-m", "--message", help="Message to hash argument", required=True)

        argument = parser.parse_args()
        message_to_hash_and_sign = argument.message

        print('Message: ', message_to_hash_and_sign)
        sha256hash = SHA256.new(message_to_hash_and_sign.encode()).digest()
        print("SHA-256 hash :", binascii.hexlify(sha256hash))
        
        sha3_256 = hashlib.sha3_256(message_to_hash_and_sign.encode()).digest()
        print("SHA3-256 hash :", binascii.hexlify(sha3_256))
        
        blake2s = hashlib.new('blake2s', message_to_hash_and_sign.encode()).digest()
        print("BLAKE2s hash :", binascii.hexlify(blake2s))
        
        ripemd160 = hashlib.new('ripemd160', message_to_hash_and_sign.encode()).digest()
        print("RIPEMD-160 hash :", binascii.hexlify(ripemd160))
        
        keccak256 = keccak.new(data=bytearray(message_to_hash_and_sign.encode()), digest_bits=256).digest()
        print("Keccak256 hash :", binascii.hexlify(keccak256))

if __name__ == "__main__":
    app = CommandLine()