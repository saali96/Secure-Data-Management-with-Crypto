from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util import Padding, number
from Crypto.IO import PEM

import random
import os

# Generate a new RSA key pair with a customizable key size that is 256
# in our case because we are allowed to select between 192 and 256 bits
def generate_rsa_key_pair(keySize=3072):
    """ RSA key size  NISTECC key size
                    
        1024 bits	  192 bits	         
        2048 bits	  224 bits	         
        3072 bits	  256 bits	"""
    return RSA.generate(keySize)

# Generate an AES key with customizable key size that is 256
# in our case because we are allowed to select between 192 and 256 bits
def generate_aes_key(keySize = 32):
    """Bits   Bytes
       192    24
       256    32"""
    return os.urandom(keySize)

# Encrypting the message using AES in CBC mode with default block size to 128
def aes_encrypt(message, key, block_size=128):
    # Generating a random IV
    iv = os.urandom(block_size // 8)
    # Padding the message
    padded_message = Padding.pad(message, block_size // 8)
    # Creating the cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Encrypting the message
    encrypted_message = cipher.encrypt(padded_message)
    return (iv, encrypted_message)

# Decrypting the message using AES in CBC mode with default block size to 128
def aes_decrypt(encrypted_message, key, iv, block_size=128):
    # Creating the cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypting the message
    message = cipher.decrypt(encrypted_message)
    # Removing the padding from the message
    padding_length = message[-1]
    return message[:-padding_length]

# Generating the signature for the message with RSA using SHA-256 to generate hash
# it'll accept private key and message in parameter
def generate_signature(private_key, message):
    h = SHA256.new(message)
    signer = PKCS1_v1_5.new(private_key)
    return signer.sign(h)

# Verifying the signature for the message with RSA using SHA-256 to generate hash
# # it'll accept public key, signature and message in parameter
def verify_signature(public_key, message, signature):
    """Verify a signature for a message using RSA"""
    h = SHA256.new(message)
    verifier = PKCS1_v1_5.new(public_key)
    return verifier.verify(h, signature)

# Generating an RSA key pair
key_pair = generate_rsa_key_pair()
private_key = key_pair.export_key()
public_key = key_pair.publickey().export_key()

originalMessage = b'My name is Syed Asad Ali and my registration number is 2207947'
print("ORIGINAL MESSAGE", originalMessage)
print("----------------")

# Converting the private key to a bytes object
private_key_bytes = key_pair.export_key()

# Importing the private key from the bytes object
private_key = RSA.import_key(private_key_bytes)

# Converting the public key to bytes
public_key_bytes = PEM.encode(public_key, "PUBLIC KEY")

# Converting the private key bytes to a PEM string
public_key_pem = PEM.decode(public_key_bytes)[0]

# Import the private key from the PEM string
public_key = RSA.import_key(public_key_pem)

# Generating an AES key
aes_key = generate_aes_key()

# Encrypting the message using the AES key
iv, encrypted_message = aes_encrypt(originalMessage, aes_key)
print("Encrypted Message", encrypted_message)
print("----------------")

# Importing the PKCS1_OAEP module and create an PKCS1_OAEP object for encryption of the AES key
encryptor = PKCS1_OAEP.new(public_key)

# Encrypting the AES key using the PKCS1_OAEP object
encrypted_aes_key = encryptor.encrypt(aes_key)

# Generating a signature for the message using the private key
signature = generate_signature(private_key, originalMessage)

# Packing the encrypted message, encrypted AES key, and signature into a single packet
packet = encrypted_aes_key + encrypted_message + signature

# Send the packet to the recipient

# To decrypt the message, the recipient can do the following:

# Import the PKCS1_OAEP module and create an PKCS1_OAEP object for decrypting the encrypted AES key
decryptor = PKCS1_OAEP.new(private_key)

# Use the PKCS1_OAEP object to decrypt the encrypted AES key
decrypted_aes_key = decryptor.decrypt(encrypted_aes_key)

# Use the decrypted AES key and the IV to decrypt the encrypted message
decrypted_message = aes_decrypt(encrypted_message, decrypted_aes_key, iv)

# Verify the signature for the decrypted message using the public key
is_signature_valid = verify_signature(public_key, decrypted_message, signature)

if is_signature_valid:
    # The signature is valid, so the message can be trusted
    print("The message is authentic and the decrypted message is:", decrypted_message)
else:
    # The signature is invalid, so the message may not be authentic
    print("The message is not authentic!")





