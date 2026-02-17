import os
import sys

from Crypto.Random import get_random_bytes as rand
from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey


def gen_sym_key( n: int = 16 ) -> bytes:
    """
    Generates a random 16-byte key for AES encryption.
    :return: Randomly generated key, in bytes format.
    """
    k = rand(16)  # generate a random 16-byte key
    return k


def gen_asym_key( n: int = 2048 ) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """
    Generates a pair of asymmetric keys (public and private) for encryption and decryption.
    :return: A tuple containing the generated public key and private key.
    """
    kj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=n,
    )

    ki = kj.public_key()
    return ki, kj


def save_asym_keys_to_files(public_key, private_key, name):
    """
    Saves the generated asymmetric keys to separate PEM files for later use.
    :param public_key: The public key to be saved, in RSAPublicKey format.
    :param private_key: The private key to be saved, in RSAPrivateKey format.
    :param name: The base name for the key files (without extension). The private key will be saved as {name}_private.pem and the public key as {name}_public.pem.
    :return: None
    """
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,  # PKCS8 is a widely supported format
        encryption_algorithm=NoEncryption()
    )

    # Serialize public key to PEM format (no encryption needed)
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
    try:
        mode = sys.argv[1].lower() # Extract mode, either "s" for symmetric or "a" for asymmetric
        size = None
        name = None

        if len(sys.argv) > 2:
            size = sys.argv[1].lower()

        if len(sys.argv) > 3:
            name = sys.argv[2].lower() # Extract name for the key file(s)

        name = name if name else "k"

        if mode == "s":
            key = gen_sym_key() if size is None else gen_sym_key( int(size) )
            with open(f"{name}.key", 'wb') as f:
                f.write(key)
            print(">> Symmetric key generated and saved to k.key")

        elif mode == "a":
            public_k, private_k = gen_asym_key() if size is None else gen_asym_key( int(size) )
            save_asym_keys_to_files(public_k, private_k, name)
            print(">> Asymmetric key pair generated and saved to public.key and private.key")

    except Exception as e:
        print(f">> There was an error: {e}")


if __name__ == "__main__":
    run()
