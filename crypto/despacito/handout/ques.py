from Crypto.Cipher import DES
import base64
from FLAG import flag


def pad(plaintext):
    while len(plaintext) % 8 != 0:
        plaintext += b"*"
    return plaintext

def enc(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(plaintext))


key = "E1E1E1E1F0F0F0F0".encode().decode("utf-8")
key = bytes.fromhex("E1E1E1E1F0F0F0F0")
plaintext = pad(flag)
print(enc(plaintext, key).decode())
