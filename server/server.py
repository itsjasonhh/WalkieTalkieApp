#!/usr/bin/env python3
"""
    Script to handle server socket implementation for CSE 234 Project. (Listener)
"""
import socket
import logging
from server.client_thread import ClientThread

MAX_CONNECTIONS = 5

class Server(object):
    def __init__(self, host, port, public_key, private_key):
        """
        Default constructor for the server implementation
        """
        self.host = host
        self.port = port
        self.public_key = public_key
        self.private_key = private_key
        self.serversocket = None

    def init(self):
        """
        Function to initialize socket
        """
        # Create an INET, STREAMing socket
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind socket to a public host and port
        self.serversocket.bind((self.host, self.port))

        # Listen
        self.serversocket.listen(MAX_CONNECTIONS)

    def run(self):
        """
        Function used to run the tcp server and accept connections
        """
        while True:
            logging.info('Waiting for connection...')
            (clientsocket, address) = self.serversocket.accept()

            ct = ClientThread(clientsocket, address, self.public_key, self.private_key)
            ct.run()
