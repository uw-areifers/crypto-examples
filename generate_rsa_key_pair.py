from Crypto.PublicKey import RSA
import argparse


class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Description for my parser")
        parser.add_argument("-pn", "--prepending", help="File name prepending argument", required=True)

        argument = parser.parse_args()
        prepend = argument.prepending
        private_key_file_name = prepend + '_private_key.pem'
        public_key_file_name = prepend + '_public_key.pem'

        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open(private_key_file_name, "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open(public_key_file_name, "wb")
        file_out.write(public_key)
        file_out.close()


if __name__ == "__main__":
    app = CommandLine()