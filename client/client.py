#!/usr/bin/env python3
"""
    Script to start a client connection to server. (Talker)
"""
import socket

BUFFER_SIZE = 4096

class Client(object):
    def __init__(self, server, port):
        """
        Default constructor for the client implementation
        """
        self.server = server
        self.port = port
        self.clientsocket = None

    def init(self):
        """
        Function to initialize client socket
        """
        # Create an INET, STREAMing socket
        self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to server
        self.clientsocket.connect((self.server, self.port))

    def run(self):
        """
        Function used to run client connection to server
        """
        REQUEST = '100000002{}\n'
        self.clientsocket.sendall(bytes(REQUEST, 'UTF-8'))

        while True:
            in_data = self.clientsocket.recv(BUFFER_SIZE)
            msg = in_data.decode()

            if msg == '200000002{}\n':
                print('Response Sent From Listener: {}'.format(msg))
                out_data = input('Input File Header: ')
                self.clientsocket.sendall(bytes(out_data, 'UTF-8'))

            break

