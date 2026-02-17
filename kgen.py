# Key Generator V2 - L3 Ciberseguridad
# Author: Adrian Velasquez

import sys

from Crypto.Random import get_random_bytes as rand
from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey


class KeyGeneratorV2:

    def __init__( self, n_sym: int = 128, n_asym: int = 2048, name: str = "k" ):
        """
        Initializes the KeyGeneratorV2 class with default parameters for symmetric and asymmetric key generation.
        :param n_sym: The size of the symmetric key to be generated, in bytes. Default is 16 bytes (128 bits) for AES-128.
        :param n_asym: The size of the asymmetric key to be generated, in bits. Default is 2048 bits for RSA.
        :param name: The base name for the key file(s) to be saved. Default is "k". For symmetric keys, the file will be saved as {name}.key. For asymmetric keys, the private key will be saved as {name}_private.pem and the public key as {name}_public.pem.
        """
        self.n_sym = n_sym
        self.n_asym = n_asym
        self.name = name

    def gen_sym_key( self, n: int = None ) -> bytes:
        """
        Generates a random symmetric key for encryption and decryption.
        :param n: The size of the key, in bits. Default is 128 bits (16 bytes) for AES-128. If n is provided, it will be used instead of the default n_sym.
        :return: Randomly generated key, in bytes format.
        """
        n = n if n else self.n_sym
        k = rand( n//8 )  # generate a random 16-byte key, n is in bits, so we divide by 8 to get the number of bytes
        return k

    def gen_asym_key( self, n: int = None ) -> tuple[RSAPublicKey, RSAPrivateKey]:
        """
        Generates a pair of asymmetric keys (public and private) for encryption and decryption.
        :param n: The size of the key to be generated, in bits. Default is 2048 bits for RSA.
        :return: A tuple containing the generated public key and private key.
        """
        n = n if n else self.n_asym
        kj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=n,
        )

        ki = kj.public_key()
        return ki, kj

    def save_sym_key_to_file( self, key: bytes, name: str = None ):
        """
        Saves the generated symmetric key to a file for later use.
        :param key: The symmetric key to be saved, in bytes format.
        :param name: The name of the key file (without extension). The key will be saved as {name}.key. Default is "k".
        :return: None
        """
        name = name if name else self.name
        with open(f"{name}.key", 'wb') as f:
            f.write(key)
        print(f"Symmetric key saved to {name}.key")

    def save_asym_keys_to_files( self, public_key, private_key, name ):
        """
        Saves the generated asymmetric keys to separate PEM files for later use.
        :param public_key: The public key to be saved, in RSAPublicKey format.
        :param private_key: The private key to be saved, in RSAPrivateKey format.
        :param name: The base name for the key files (without extension). The private key will be saved as {name}_private.pem and the public key as {name}_public.pem.
        :return: None
        """
        name = name if name else self.name
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,  # PKCS8 is a widely supported format
            encryption_algorithm=NoEncryption()
        )

        # Serialize public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo  # SPKI is common for public keys
        )

        with open(f"{name}_private.pem", "wb") as f:
            f.write(private_pem)
        with open(f"{name}_public.pem", "wb") as f:
            f.write(public_pem)
        print("Keys saved to private_key.pem and public_key.pem")


def run():
    """
    Runs the key generation process based on the command-line arguments provided.
    :return: None
    """
    generator = KeyGeneratorV2()
    try:
        mode = None
        size = None
        name = None

        if len(sys.argv) > 1:
            mode = sys.argv[1].lower()  # Extract mode, either "s" for symmetric or "a" for asymmetric

        if len(sys.argv) > 2:
            size = sys.argv[1].lower()

        if len(sys.argv) > 3:
            name = sys.argv[2].lower() # Extract name for the key file(s)

        if mode == "s" or None:
            key = generator.gen_sym_key() if size is None else generator.gen_sym_key( int(size) )
            generator.save_sym_key_to_file( key, name )
            print(">> Symmetric key generated and saved to k.key")

        elif mode == "a":
            public_k, private_k = generator.gen_asym_key() if size is None else generator.gen_asym_key( int(size) )
            generator.save_asym_keys_to_files(public_k, private_k, name)
            print(">> Asymmetric key pair generated and saved to public.key and private.key")

        else:
            ValueError("Invalid mode. Use 's' for symmetric key or 'a' for asymmetric key pair.")

    except Exception as e:
        print(f">> There was an error: {e}")
        print(">> Usage: python kgen.py <mode> <size> <name>\n"
              "   mode: 's' for symmetric key, 'a' for asymmetric key pair\n"
              "   size: (optional) key size in bytes for symmetric or bits for asymmetric (default: 16 bytes for symmetric, 2048 bits for asymmetric)\n"
              "   name: (optional) base name for the key file(s) (default: 'k')\n"
              "Example: python3 kgen.py s 32 my_symmetric_key\n"
              "         python3 kgen.py a 4096 my_asymmetric_keys")


if __name__ == "__main__":
    run()
