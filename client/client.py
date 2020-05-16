#!/usr/bin/env python3
"""
    Script to start a client connection to server. (Talker)
"""
import socket
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
        self.request = '{0}{1}{2}'.format('1', length_str, self.json_request)

    def run(self):
        """
        Function used to run client connection to server
        """
        self.build_request()
        self.clientsocket.sendall(bytes(self.request, 'UTF-8'))

        while True:
            in_data = self.clientsocket.recv(BUFFER_SIZE)
            msg = in_data.decode()

            if msg == '200000002{}\n':
                print('Response Sent From Listener: {}'.format(msg))
                out_data = input('Input File Header: ')
                self.clientsocket.sendall(bytes(out_data, 'UTF-8'))

            break

