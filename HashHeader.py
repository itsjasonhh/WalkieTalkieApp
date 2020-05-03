import hashlib
import base64
#file is encrypted using simon in counter mode using k1
#hash is calculated using k2
#k1 = 0x000000...000 for 256 bits
#k2 = 0x010000...000 for 256 bits

#Assuming k2 is an int in hex, encrypted_message is a string of binary data with no 0b
def create_header(k2, encrypted_message):
    b = bin(k2)[2:]
    b += encrypted_message
    b = b.encode()
    value = hashlib.sha3_256(b).hexdigest()
    return str(base64.b64encode(value.encode('ascii')))[2:-1]

#Testing outputs
#print((create_header(0x0001,'1000101')))
