#! /usr/share/python3

# importing cryptography modules
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# importing system modules 
import os
import base64

# some raw data to fetch for testing
password = "Pyth0nHack3r24"
private_key = "simplicity_is_the_best_sofastication"

def encrypt(private_key, password):

    # Derive a secure encryption key using PBKDF2 with the salt
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,  # Adjust the number of iterations for desired security
        length=32
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # Encrypt the private key with the derived key
    fernet = Fernet(key)
    encrypted_key = fernet.encrypt(private_key.encode())

    return salt, encrypted_key

def decrypt(encrypted_key, salt, password):

    # Derive the key using the fetched salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,  # Same number of iterations as during encryption
        length=32
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Decrypt the private key
    fernet = Fernet(key)
    decrypted_key = fernet.decrypt(encrypted_key).decode()
    return decrypted_key

print("Get the encryted value: ")
salt, encrypted_key = encrypt(private_key, password)
print(encrypted_key.decode())

print("Decrpyted value: ")
decrypted_key = decrypt(encrypted_key, salt, password)
print(decrypted_key)

