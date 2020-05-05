#Code taken from https://github.com/bozhu/NSA-ciphers/blob/master/simon.py by Bo Zhu
import time
import random
class SIMON:
    """
    one of the two lightweight block ciphers designed by NSA
    this one is optimized for hardware implementation
    """
    def __init__(self, block_size, key_size, master_key=None):
        self.block_size = block_size
        self.key_size = key_size
        self.__num_rounds = 72
        self.__const_seq = (1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1)
        assert len(self.__const_seq) == 62
        self.__dim = block_size // 2
        self.__mod = 1 << self.__dim
        if master_key is not None:
            self.change_key(master_key)

    def __lshift(self, x, i=1):
        return ((x << i) % self.__mod) | (x >> (self.__dim - i))

    def __rshift(self, x, i=1):
        return ((x << (self.__dim - i)) % self.__mod) | (x >> i)

    def change_key(self, master_key):
        assert 0 <= master_key < (1 << self.key_size)
        c = (1 << self.__dim) - 4
        m = self.key_size // self.__dim
        self.__round_key = []
        for i in range(m):
            self.__round_key.append(master_key % self.__mod)
            master_key >>= self.__dim
        for i in range(m, self.__num_rounds):
            k = self.__rshift(self.__round_key[-1], 3)
            if m == 4:
                k ^= self.__round_key[-3]
            k ^= self.__rshift(k) ^ self.__round_key[-m]
            k ^= c ^ self.__const_seq[(i - m) % 62]
            self.__round_key.append(k)

    def __feistel_round(self, l, r, k):
        f = (self.__lshift(l) & self.__lshift(l, 8)) ^ self.__lshift(l, 2)
        return r ^ f ^ k, l

    def encrypt(self, plaintext):
        l = plaintext >> self.__dim
        r = plaintext % self.__mod
        for i in range(self.__num_rounds):
            l, r = self.__feistel_round(l, r, self.__round_key[i])
        ciphertext = (l << self.__dim) | r
        return ciphertext

    def decrypt(self, ciphertext):
        l = ciphertext >> self.__dim
        r = ciphertext % self.__mod
        for i in range(self.__num_rounds - 1, -1, -1):
            r, l = self.__feistel_round(r, l, self.__round_key[i])
        plaintext = (l << self.__dim) | r
        return plaintext


# time = bin(int(time.time()*1000000))[2:]
# while len(time) < 32:
#     time = '0' + time
# while len(time) < 64:
#     time = time + '0'
# print(time)
# print(len(time))
# print(hex(int(time,16)))
# print(hex(int(time,16)+1))
# print(len(bin(0x04))-2)
# print(bin(0x04)[2:])

#plaintext,nonce,key are all ints, returns a string of hex digits
# def countermode_encrypt(plaintext,nonce,key):
#     n = len(bin(plaintext))-2
#     number_of_blocks = n // 128
#     remainder = n%128
#     if remainder != 0:
#         number_of_blocks += 1
#     #creating the nonce (iv) and counter
#     iv = bin(nonce)[2:]
#     while len(iv) < 64:
#         iv = '0' + iv
#     while len(iv) < 128:
#         iv = iv + '0'
#     iv = int(iv,2)
#
#     simon = SIMON(128,256,key)
#     ciphertext = ''
#     plain = bin(plaintext)[2:]
#
#     #returns as a string of hex digits
#     if number_of_blocks == 1:
#         ek = bin(simon.encrypt(iv))[2:]
#         cipher = plaintext ^ int(ek[0:n],2)
#         return hex(cipher)[2:]
#
#     #returns as a string of hex digits
#     elif number_of_blocks > 1 and remainder == 0:
#         for i in range(number_of_blocks):
#             ek = simon.encrypt(iv)
#             cipher = ek ^ int(plain[128*i:128*(i+1)],2)
#             ciphertext += hex(cipher)[2:]
#             iv += 1
#         return ciphertext
#     else:
#         for i in range(number_of_blocks-1):
#             ek = simon.encrypt(iv)
#             cipher = ek ^ int(plain[128*i:128*(i+1)],2)
#             ciphertext += hex(cipher)[2:]
#             iv += 1
#
#         last = bin(simon.encrypt(iv))[2:]
#         cipher = int(plain[-remainder:],2) ^ int(last[:remainder],2)
#         ciphertext += hex(cipher)[2:]
#         return ciphertext
#
# #ciphertext, nonce, key are all integers
# def countermode_decrypt(ciphertext, nonce, key):
#     n = len(bin(ciphertext))-2
#     number_of_blocks = n // 128
#     remainder = n%128
#     if remainder != 0:
#         number_of_blocks += 1
#     iv = bin(nonce)[2:]
#     while len(iv) < 64:
#         iv = '0' + iv
#     while len(iv) < 128:
#         iv = iv + '0'
#     iv = int(iv,2)
#
#     simon = SIMON(128,256,key)
#     plaintext = ''
#     ciph = bin(ciphertext)[2:]
#
#     #returns as a string of hex digits
#     if number_of_blocks == 1:
#         dk = bin(simon.encrypt(iv))[2:]
#         plain = ciphertext ^ int(dk[0:n],2)
#         return hex(plain)[2:]
#
#     #returns as a string of hex digits
#     elif number_of_blocks > 1 and remainder == 0:
#         for i in range(number_of_blocks):
#             dk = simon.encrypt(iv)
#             plain = dk ^ int(ciph[128*i:128*(i+1)],2)
#             plaintext += hex(plain)[2:]
#             iv += 1
#         return plaintext
#     else:
#         for i in range(number_of_blocks-1):
#             dk = simon.encrypt(iv)
#             plain = dk ^ int(ciph[128*i:128*(i+1)],2)
#             plaintext += hex(plain)[2:]
#             iv += 1
#
#         last = bin(simon.encrypt(iv))[2:]
#         plain = int(ciph[-remainder:],2) ^ int(last[:remainder],2)
#         plaintext += hex(plain)[2:]
#         return plaintext




# print(countermode_decrypt(0x25,nonce, key))

#encrypt and decrypt are not undoing each other
#maybe start by splitting plaintext into 128 bit blocks (as strings) and put them in an array
#then manually update iv in a for loop as you encrypt each entry in the array.

#returns as string of binary digits
def countermode_encrypt(message,nonce,key):
    m = bin(message)[2:]
    n = len(m)
    remainder = n%128
    number_of_blocks = n//128
    #splitting message into 128-bit blocks
    if remainder != 0:
        number_of_blocks += 1
    list_of_blocks = []
    if number_of_blocks == 1:
        list_of_blocks.append(m)
    if number_of_blocks > 1 and remainder == 0:
        for i in range(number_of_blocks):
            list_of_blocks.append(m[i*128 : (i+1)*128])
    if number_of_blocks > 1 and remainder != 0:
        for i in range(number_of_blocks-1):
            list_of_blocks.append(m[i*128 : (i+1)*128])
        list_of_blocks.append(m[-remainder:])

    simon = SIMON(128,256,key)
    ciphertext = []
    for i in list_of_blocks:
        ek = simon.encrypt(nonce)
        #full block of plaintext (128 bits)
        if len(i) == 128:
            cipher = ek ^ int(i,2)
            # cipher = bin(cipher)[2:]
            # while len(cipher) < len(i):
            #     cipher = '0' + cipher
            ciphertext.append(cipher)
        #partial block of plaintext (< 128 bits)
        else:
            cipher = ek ^ int(i,2)
            #cipher = int(i,2) ^ int(bin(ek)[2 : len(i)+2],2)
            # cipher = bin(cipher)[2:]
            # while len(cipher) < len(i):
            #     cipher = '0' + cipher
            ciphertext.append(cipher)

        nonce += 1
    return ciphertext

def countermode_decrypt(ciphertext,nonce,key):
    c = bin(ciphertext)[2:]
    n = len(c)
    remainder = n%128
    number_of_blocks = n//128
    if remainder != 0:
        number_of_blocks += 1
    list_of_blocks = []
    if number_of_blocks == 1:
        list_of_blocks.append(c)
    if number_of_blocks > 1 and remainder == 0:
        for i in range(number_of_blocks):
            list_of_blocks.append(c[i*128 : (i+1)*128])
    if number_of_blocks > 1 and remainder != 0:
        for i in range(number_of_blocks-1):
            list_of_blocks.append(c[i*128 : (i+1)*128])
        list_of_blocks.append(c[-remainder:])
    simon = SIMON(128,256,key)
    plaintext = []
    for i in list_of_blocks:
        dk = simon.encrypt(nonce)
        if len(i) == 128:
            plain = dk ^ int(i,2)
            # plain = bin(plain)[2:]
            # while len(plain) < len(i):
            #     plain = '0' + plain
            plaintext.append(plain)
        else:
            plain = dk ^ int(i,2)
            #plain = int(i,2) ^ int(bin(dk)[2 : len(i)+2],2)
            # plain = bin(plain)[2:]
            # while len(plain) < len(i):
            #     plain = '0' + plain
            plaintext.append(plain)
        nonce += 1
    return plaintext


nonce = 0x0
key = 0x0
#message = 10
ciphertext = 273667375284173757969559178356596630591

# a = countermode_encrypt(message,nonce,key)
# b = countermode_decrypt(ciphertext,nonce,key)
# print(a)
# print(b)

with open("recording.m4a",'rb') as file:
    data = file.read()
    message = int(data.hex(),16)

