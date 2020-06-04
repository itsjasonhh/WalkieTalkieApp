#!/usr/bin/env python3
"""
    Script to start a client connection to server. (Talker)
"""
import socket
import json
import datetime
import copy
import hashlib
import math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from encryptlib.json_message import JsonMessage
from encryptlib.print_helper import PrintHelper
from encryptlib.SimonCTR import countermode_encrypt, countermode_decrypt
from keylib.keys import g, p

BUFFER_SIZE = 32768
KEY_BIT_SIZE = 4000

class Client(object):
    def __init__(self, server, port, public_key, private_key):
        """
        Default constructor for the client implementation
        """
        self.server = server
        self.port = port
        self.clientsocket = None
        self.request = None
        self.public_key = public_key
        self.private_key = private_key
        self.pprint = PrintHelper()

    def init(self):
        """
        Function to initialize client socket
        """
        # Create an INET, STREAMing socket
        self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to server
        self.clientsocket.connect((self.server, self.port))

    def create_sess_key(self):
        """
        Function to create sess key
        """
        # 1. create a 256 bit session key
        key_int = int.from_bytes(get_random_bytes(32), byteorder='little')
        tod_int = int(datetime.datetime.now().timestamp() * 1000)

        self.sess_key = {
            "key": key_int,
            "ToD": tod_int
        }

        key_str = str(key_int)
        tod_str = str(tod_int)

        sess_key = {
            "key": key_str,
            "ToD": tod_str
        }

        self.json_request.dhke_data["sess_key"] = sess_key

    def generate_agreed_diffie_key(self):
        self.D_ab = pow(int(self.json_response["payload"]["agreement_data"]["diffie_pub_k"]), self.d_a, p)

    def generate_k1_k2(self):
        """
        Function used to create k1 and k2 keys
        """
        # D_ab int to bytes
        D_ab = copy.copy(self.D_ab)

        data_int_in_binary = bin(D_ab)[2:]
        remainder = len(data_int_in_binary) % 8

        if remainder != 0:
            pad = '0' * (8 - remainder)
            data_int_in_binary = '{0}{1}'.format(pad, data_int_in_binary)

        concat_bytes = '{0}{1}'.format('00000001', data_int_in_binary)
        length = int(len(concat_bytes) / 8)
        concat_int = int(concat_bytes, 2)
        concat_bytes = concat_int.to_bytes(length, byteorder='little')

        m = hashlib.sha3_256()
        m.update(concat_bytes)
        self.k1 = int(m.hexdigest(), 16)

        concat_bytes = '{0}{1}'.format('00000010', data_int_in_binary)
        length = int(len(concat_bytes) / 8)
        concat_int = int(concat_bytes, 2)
        concat_bytes = concat_int.to_bytes(length, byteorder='little')

        m = hashlib.sha3_256()
        m.update(concat_bytes)
        self.k2 = int(m.hexdigest(), 16)

        self.t = self.sess_key["ToD"]

    def encrypt_sess_key(self):
        """
        Function used to encrypt the sess_key object by the receivers public key
        """
        sess_key = json.dumps(self.json_request.dhke_data["sess_key"])

        raw_bytes = sess_key.encode('utf-8')
        sess_key_int = int.from_bytes(raw_bytes, byteorder='little')

        sess_key_encrypted = pow(sess_key_int, self.public_key.e, self.public_key.n)

        self.json_request.dhke_data["sess_key"] = str(sess_key_encrypted)

    def hash_sess_key(self):
        """
        Function used to hash the sess key, needed to encryp the payload
        """
        m = hashlib.sha3_256()
        raw_sess_key = json.dumps(self.json_request.dhke_data["sess_key"])
        m.update(bytes(raw_sess_key, 'UTF-8'))

        byte_value = m.digest()
        hash_sess_str = str(int.from_bytes(byte_value, byteorder='little'))

        self.json_request.dhke_data["payload"]["agreement_data"]["hash_sess_key"] = hash_sess_str

    def generate_diffie_pub_key(self):
        """
        Function used to generate the our public diffie hellman key based on g and p values
        """
        # TODO: need to generate correct size Diffie Hellman priv key
        self.d_a = int.from_bytes(get_random_bytes(512), byteorder='little')

        diffie_pub_key = pow(g, self.d_a, p)
        diffie_pub_key_str = str(diffie_pub_key)

        self.json_request.dhke_data["payload"]["agreement_data"]["diffie_pub_k"] = diffie_pub_key_str

    def sign_agreement_data(self):
        """
        Function used to sign the payload messgae before encryption
        """
        # get raw data_agreement info
        data_raw = json.dumps(self.json_request.dhke_data["payload"]["agreement_data"])

        m = hashlib.sha3_256()
        m.update(bytes(data_raw, 'UTF-8'))

        hash_bytes = m.digest()
        hash_int = int.from_bytes(hash_bytes, byteorder='little')

        signature = str(pow(hash_int, self.private_key.d, self.public_key.n))
        self.json_request.dhke_data["payload"]["signature"] = signature

    def encrypt_agreement_data(self):
        """
        Function used to encrypt the agreement data using conter mode.
        """
        data_raw = json.dumps(self.json_request.dhke_data["payload"])
        data_bytes = bytes(data_raw,'UTF-8')
        data_int = int.from_bytes(data_bytes, byteorder='little')
        data_int_in_binary = bin(data_int)[2:]

        """
            Check to see if binary data is divisible by 8
        """
        remainder = len(data_int_in_binary) % 8

        if remainder != 0:
            pad = '0' * (8 - remainder)
            data_int_in_binary = '{0}{1}'.format(pad, data_int_in_binary)

        m1_c = countermode_encrypt(data_int_in_binary, self.sess_key["ToD"], self.sess_key["key"])
        m1_c_dec = int(m1_c, 2)
        m1_c_str = str(m1_c_dec)

        self.json_request.dhke_data["payload"] = m1_c_str

    def build_request(self):
        """
        Function used to build the initial request
        """
        self.json_request = JsonMessage()

        self.create_sess_key()
        self.hash_sess_key()
        self.encrypt_sess_key()
        self.generate_diffie_pub_key()

        self.sign_agreement_data()

        self.encrypt_agreement_data()

        # Determine length of JSON payload
        length = len(self.json_request.__str__())
        length_str = '{:08d}'.format(length)

        # form entire request
        self.request = '{0}{1}{2}'.format('1', length_str, self.json_request.__str__())
        # self.pprint.sent('\nRequest <<<\n----------\n{0}\n----------'.format(self.request))

    def is_valid_response(self, response):
        """
        Function used to validate response
        """
        resp_type = response[0]
        resp_length = response[1:9]

        if resp_type != '2':
            return False

        try:
            length  = int(resp_length)
        except ValueError:
            # sent us data that is NOT just digits 0-9
            return False

        payload = response[9: length + 9]

        try:
            self.json_response = json.loads(payload)
        except json.JSONDecodeError:
            # invalid JSON object
            return False

        # self.pprint.received('\nResponse >>>\n----------\n{0}\n----------'.format(response))
        return True

    def process_response(self):
        """
        Function used to process the response from the server/listener
        """
        """
            Begin Processing response JSON object
        """
        self.decrypt_sess_key()
        self.decrypt_payload()
        is_valid_sign = self.verify_sign()

        if is_valid_sign:
            # continue processing
            is_valid_hash = self.verify_hash()

            if is_valid_sign:
                # Now need to start building response
                # hence return and call self.build_response()
                return
            else:
                #close connection
                pass
        else:
            # need to close connection
            pass

    def verify_hash(self):
        """
        Function used to verify the hash of the incoming message
        """
        raw_sess_key = json.dumps(self.json_response["sess_key"])

        m = hashlib.sha3_256()
        m.update(bytes(raw_sess_key, 'utf-8'))
        byte_value = m.digest()
        hash_sess_str = str(int.from_bytes(byte_value, byteorder='little'))

        if hash_sess_str == self.json_response["payload"]["agreement_data"]["hash_sess_key"]:
            return True
        else:
            return False



    def verify_sign(self):
        """
        Function to verify signature of packet 1 from talker
        """
        signature_raw = self.json_response["payload"]["signature"]
        int_val = int(signature_raw)

        sign_val = pow(int_val, self.public_key.e, self.public_key.n)

        data_raw = json.dumps(self.json_response["payload"]["agreement_data"])
        m = hashlib.sha3_256()
        m.update(bytes(data_raw, 'utf-8'))

        hash_bytes = m.digest()
        hash_int = int.from_bytes(hash_bytes, byteorder='little')

        if sign_val == hash_int:
            return True
        else:
            return False



    def decrypt_payload(self):
        """
        Function used to decrypt payload of request
        """
        key = int(self.json_response["sess_key"]["key"])
        nonce = self.sess_key["ToD"]

        data_raw = self.json_response["payload"]
        data_int = int(data_raw)
        data_int_in_binary = bin(data_int)[2:]

        """
            Check to see if binary data is divisible by 8
        """
        remainder = len(data_int_in_binary) % 8

        if remainder != 0:
            pad = '0' * (8 - remainder)
            data_int_in_binary = '{0}{1}'.format(pad, data_int_in_binary)


        m2_c = countermode_decrypt(data_int_in_binary, nonce, key)
        m2_c_dec = int(m2_c, 2)
        m2_c_str = str(m2_c_dec)

        length = int(math.ceil(m2_c_dec.bit_length() / 8))

        payload_str = m2_c_dec.to_bytes(length, byteorder='little')
        # TODO: Something's this fails, idk why
        payload_str = payload_str.decode('utf-8')

        self.json_response["payload"] = json.loads(payload_str)


    def decrypt_sess_key(self):
        """
        Function used to decrypt the sess_key we received in response from server/listener
        """
        data_raw = self.json_response["sess_key"]
        data_int = int(data_raw)

        sess_key_decrypted = pow(data_int, self.private_key.d, self.private_key.n)

        length = int(math.ceil(sess_key_decrypted.bit_length() / 8))

        sess_str = sess_key_decrypted.to_bytes(length, byteorder='little')
        sess_str = sess_str.decode('utf-8')

        self.json_response["sess_key"] = json.loads(sess_str)

    def encrypt_audio(self):
        with open("encryptlib/recording.m4a", 'rb') as file:
            data = file.read()
            message = data.hex()
            self.D = countermode_encrypt(bin(int(message, 16))[2:],self.t,self.k1)
            self.D = int(self.D, 2)
            self.D = str(self.D)

    def run(self):
        """
        Function used to run client connection to server
        """
        self.build_request()
        self.clientsocket.sendall(bytes(self.request, 'UTF-8'))

        while True:
            in_data = self.clientsocket.recv(BUFFER_SIZE)
            msg = in_data.decode()

            if self.is_valid_response(msg):
                # self.process_response()
                self.process_response()
                self.generate_agreed_diffie_key()
                self.generate_k1_k2()

                """
                    Alice calculates message 3 and D
                """
                self.encrypt_audio()
                # 3. If valid response we need to send audio
                    #Create D = Encrypted audio using simon ctr with k1, ToD as key/nonce
                    #Calculate tag = sha3_256(k2 || D)
                          #tag = sha3_256(k2 + D)
                    #Create m3 = {"tag":tag}
                    #Send (m3, D)
            else:
                # else close connection
                self.clientsocket.close()

            print('We encrypted!')
            break

