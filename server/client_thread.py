#!/usr/bin/env python3
"""
    Script to handle client connection as a server
"""
import threading
import json
import sys
import os

from encryptlib.json_message import JsonMessage

BUFFER_SIZE = 4096
HEADER_SIZE = 9

class ClientThread(threading.Thread):
    def __init__(self,clientsocket, client_address):
        """
        Default constructor or class handling client socket thread
        """
        threading.Thread.__init__(self)
        self.clientd = clientsocket
        self.protocol = None
        self.length = None
        self.buffer = None
        self.valid_request = False

    def run(self):
        """
        Function to handle client socket thread execution
        """
        while True:
            data = self.clientd.recv(BUFFER_SIZE)
            bytes_recv = len(data)
            msg = data.decode()

            """
                Need to determine if data is valid request else close connection
            """
            self.process_request(msg)

            """
                Close connection.
            """
            if self.valid_request:
                """
                    Send Response
                """
                self.send_response()
            else:
                break

            """
                Need to wait for File Header and Data now
            """
            data = self.clientd.recv(BUFFER_SIZE)
            msg = data.decode()

            self.process_file_header(data)
            self.clientd.close()
            break

    def send_response(self):
        """
        Function to handle sending a response to the client
        """
        response_string = '200000002{}\n'

        self.clientd.send(bytes(response_string, 'UTF-8'))

    def process_request(self, message):
        """
        Function used to process the request
        """
        if (self.is_valid_request(message[0])):
            self.protocol = message[0]
            """
                length is the # of bytes we need to read after length param
            """
            self.length = self.get_length(message[1:9])

            self.read_data(self.length, message)

            """
                Need to validate contents of the buffer
            """
            if (self.is_valid_contents()):
                self.valid_request = True
                print('Request Sent From Talker: {}'.format(message))

    def process_file_header(self, message):
        """
        Function to prcess the File Header after we have
        achieved a valid request and response from/to the client respectfully
        """
        request_type = message[0]
        length = self.get_length(message[1:9])

        # TODO: What if length is larger than our buffer? need to cover this case
        json_string = message[9:9 + length]

        # Create a json onject of File Header e.g., {"tag": "8troihjZ6pQoXcZPg\/OpcUCGE1zF+zIRLywfuMaC3+o="}
        json_data = json.loads(json_string)
        print('Received Tag: {}'.format(json_data['tag']))

    def is_valid_request(self, protocol):
        """
        Function to validate request
        """
        if protocol == '1':
            return True
        else:
            return False

    def is_valid_contents(self):
        """
        Function used to determine if contents are valid
        """
        if self.buffer == '{}\n':
            return True
        else:
            return False

    def get_length(self, length):
        """
        Function to get the value of integer value of the length
        """
        val = int(length)

        return val

    def read_data(self, length, msg):
        """
        Function used to read data based on length value
        """
        self.buffer = msg[HEADER_SIZE: HEADER_SIZE + length + 1]
