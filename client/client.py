#!/usr/bin/env python3
"""
    Script to start a client connection to server. (Talker)
"""
import socket
import json
import datetime
import copy
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from encryptlib.json_message import JsonMessage
from encryptlib.print_helper import PrintHelper
from encryptlib.SimonCTR import countermode_encrypt
from keylib.keys import g, p

BUFFER_SIZE = 4096
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
        m = hashlib.sha3_512()
        m.update(bytes(self.json_request.dhke_data["sess_key"], 'UTF-8'))

        byte_value = m.digest()
        hash_sess_str = str(int.from_bytes(byte_value, byteorder='little'))

        self.json_request.dhke_data["payload"]["agreement_data"]["hash_sess_key"] = hash_sess_str

    def generate_diffie_pub_key(self):
        """
        Function used to generate the our public diffie hellman key based on g and p values
        """
        diffie_pub_key = pow(g, self.private_key.d, p) # TODO : need to generate diffie priv key 4096
        diffie_pub_key_str = str(diffie_pub_key)

        self.json_request.dhke_data["payload"]["agreement_data"]["diffie_pub_k"] = diffie_pub_key_str

    def sign_agreement_data(self):
        """
        Function used to sign the payload messgae before encryption
        """
        # get raw data_agreement info
        data_raw = json.dumps(self.json_request.dhke_data["payload"]["agreement_data"])

        m = hashlib.sha3_512()
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
        m1_c = countermode_encrypt(data_int_in_binary, self.sess_key["ToD"],self.sess_key["key"])
        m1_c_dec = int(m1_c,2)
        m1_c_str = str(m1_c_dec)
        self.json_request.dhke_data["payload"] = m1_c_str

    def build_request(self):
        """
        Function used to build the initial request
        """
        self.json_request = JsonMessage()

        self.json_request.set_json_payload()
        self.create_sess_key()
        self.encrypt_sess_key()

        self.hash_sess_key()
        self.generate_diffie_pub_key()

        self.sign_agreement_data()

        self.encrypt_agreement_data()

        # Determine length of JSON payload
        length = len(self.json_request.__str__())
        length_str = '{:08d}'.format(length)

        # form entire request
        self.request = '{0}{1}{2}'.format('1', length_str, self.json_request.__str__())
        self.pprint.sent('\nRequest <<<\n----------\n{0}\n----------'.format(self.request))

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

        self.pprint.received('\nResponse >>>\n----------\n{0}\n----------'.format(response))
        return True


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
                print('Valid Response')
                # 1. get key info
                    #Receives (m2c, ses2)
                    #Calculates m2a by decrypting ses2 using Alice's RSA private key
                    #m2a reveals sb
                    #Calculates (m2b, sig2) by countermode-decrypting m2c using sb, tod as key and nonce
                    #Verify e_kb(sig2) = sha3_512(m2b)
                    #m2b reveals hash session key h and diffie-hellman public key D_b
                    #Verify h = sha3_512(m2a)
                    #Calculate k1 and k2: k1||k2 = sha3_512(D_b ^ d_a mod p)
                
                # 2. If valid response we need to send audio
                    #Create D = Encrypted audio using simon ctr with k1, ToD as key/nonce 
                    #Calculate tag = sha3_512(k2 || D)
                    #Create m3 = {"tag":tag}
                    #Send (m3, D)

            else:
                # else close connection
                self.clientsocket.close()

            break

