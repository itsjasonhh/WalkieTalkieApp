#!/usr/bin/env python3
"""
    Script to start a client connection to server. (Talker)
"""
import socket
import json
import datetime
import copy
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from encryptlib.json_message import JsonMessage
from encryptlib.print_helper import PrintHelper

BUFFER_SIZE = 4096
KEY_BIT_SIZE = 4000

class Client(object):
    def __init__(self, server, port):
        """
        Default constructor for the client implementation
        """
        self.server = server
        self.port = port
        self.clientsocket = None
        self.request = None
        self.pprint = PrintHelper()

        # TODO: needs to be dynamic this is representative of reveiver public key
        key = RSA.generate(4000)
        public_key = key.publickey()
        self.recv_key = key
        self.recv_public_key = public_key
        #TODO: need access to the public and private keys

    def init(self):
        """
        Function to initialize client socket
        """
        # Create an INET, STREAMing socket
        self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to server
        self.clientsocket.connect((self.server, self.port))

        # Generate private and public key pairs
        self.key = RSA.generate(KEY_BIT_SIZE)

    def create_sess_key(self):
        """
        Function to create sess key
        """
        # 1. create a 256 bit session key
        key = str(int.from_bytes(get_random_bytes(KEY_BIT_SIZE), byteorder='little'))
        nonce = str(int(datetime.datetime.now().timestamp() * 1000))

        sess_key = {
            key: key,
            nonce: nonce
        }

        self.json_request.dhke_data["payload"]["sess_key"] = sess_key

    def encrypt_sess_key(self):
        """
        Function used to encrypt the sess_key object by the receivers public key
        """
        sess_key = copy.copy(self.json_request.dhke_data["payload"]["sess_key"])
        sess_key = json.dumps(sess_key)

        raw_bytes = bytes(sess_key, 'UTF-8')
        sess_key_int = int.from_bytes(raw_bytes, byteorder='little')

        sess_key_encrypted = pow(sess_key_int, self.recv_public_key.e, self.recv_public_key.n)

        sess_key_encrypted_str = str(sess_key_encrypted)

        self.json_request.dhke_data["sess_key"] = sess_key_encrypted_str


    def build_request(self):
        """
        Function used to build the initial request
        """
        self.json_request = JsonMessage()

        self.json_request.set_json_payload()
        self.create_sess_key()
        self.encrypt_sess_key()

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
                print('Valid Response')
                # 1. get key info
                # 2. If valid response we need to send audio
            else:
                # else close connection
                self.clientsocket.close()

            break

