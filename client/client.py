#!/usr/bin/env python3
"""
    Script to start a client connection to server. (Talker)
"""
import socket
import json
from encryptlib.json_message import JsonMessage

BUFFER_SIZE = 4096

class Client(object):
    def __init__(self, server, port):
        """
        Default constructor for the client implementation
        """
        self.server = server
        self.port = port
        self.clientsocket = None
        self.request = None

    def init(self):
        """
        Function to initialize client socket
        """
        # Create an INET, STREAMing socket
        self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to server
        self.clientsocket.connect((self.server, self.port))

    def build_request(self):
        """
        Function used to build the initial request
        """
        self.json_request = JsonMessage()
        self.json_request.set_json_payload()

        # Determine length of JSON payload
        length = len(self.json_request.__str__())
        length_str = '{:08d}'.format(length)

        # form entire request
        self.request = '{0}{1}{2}'.format('1', length_str, self.json_request.__str__())
        print('\nRequest <<<\n----------\n{0}\n----------'.format(self.request))

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

        print('\nResponse >>>n----------\n{0}\n----------'.format(response))
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

