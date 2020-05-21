import hashlib
import base64
import json
from encryptlib.SimonCTR import countermode_encrypt
#file is encrypted using simon in counter mode using k1
#hash is calculated using k2
#k1 = 0x000000...000 for 256 bits
#k2 = 0x010000...000 for 256 bits

#Assuming k2 is an int, encrypted_message is a string of hex digits
#Returns string encoded in base64


def create_header(message, nonce):
    k1 = 0x0000000000000000000000000000000000000000000000000000000000000000
    k2 = 0x0100000000000000000000000000000000000000000000000000000000000000
    encrypted_message = countermode_encrypt(message, nonce, k1)
    b = hex(k2)[2:]
    b += hex(int(encrypted_message))[2:]
    if len(b) % 2 != 0:
        b = '0' + b
    bytestring = bytes.fromhex(b)
    T = hashlib.sha3_256(bytestring).digest()
    value = base64.b64encode(T)
    tag_value = {"tag": value.decode()}
    tag_value_str = json.dumps(tag_value)
    length = len(tag_value_str)
    length_str = '{:08d}'.format(length)
    header = '{0}{1}{2}'.format('3', length_str, tag_value_str)
    return header


if __name__ == '__main__':
    with open("../recording.m4a", 'rb') as file:
        data = file.read()
        message = bin(int(data.hex(), 16))[2:]
        nonce = 0
        print(create_header(message, nonce))
