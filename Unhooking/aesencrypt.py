import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

# FIXED: This function now properly pads a bytes object, not a string.
def pad(s):
    padding_len = AES.block_size - len(s) % AES.block_size
    padding = bytes([padding_len]) * padding_len
    return s + padding

def aesenc(plaintext, key):
    k = hashlib.sha256(key).digest()
    # FIXED: The IV must be a bytes object.
    iv = 16 * b'\x00'
    plaintext = pad(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, iv)

    return cipher.encrypt(plaintext)


try:
    # FIXED: Open the file in binary read mode ("rb").
    plaintext = open(sys.argv[1], "rb").read()
except Exception as e:
    print(f"Error opening or reading file: {e}")
    print("Usage: %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)

# FIXED: Removed incorrect ord() call, as iterating over bytes gives integers directly.
print('unsigned char AESkey[] = { ' + ', '.join(f'0x{x:02x}' for x in KEY) + ' };')
print('unsigned char payload[] = { ' + ', '.join(f'0x{x:02x}' for x in ciphertext) + ' };')