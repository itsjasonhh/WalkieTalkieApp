import hashlib
import base64
#file is encrypted using simon in counter mode using k1
#hash is calculated using k2
#k1 = 0x000000...000 for 256 bits
#k2 = 0x010000...000 for 256 bits

#Assuming k2 is an int in hex, encrypted_message is a string of hex digits
#Returns string encoded in base64
def create_header(k2, encrypted_message):
    b = hex(k2)[2:]
    b += encrypted_message
    bytestring = bytes.fromhex(b)
    value = hashlib.sha3_256(bytestring).digest()
    b64 = base64.b64encode(value)
    return b64.decode()






