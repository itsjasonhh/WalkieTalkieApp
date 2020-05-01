#!/usr/bin/env python3
"""
    Script to handle server socket implementation for CSE 234 Project
"""
import argparse
import socket, threading

MAX_CONNECTIONS = 5
BUFFER_SIZE = 4096
HEADER_SIZE = 9

def handle_arguments():
    """
    Function used to set and handle arguments
    """
    parser = argparse.ArgumentParser(description='Server Accepting and Sending Encrypt/Decrypt Request')
    parser.add_argument('PORT', type=int,
                        help='Port for server to listen on')

    parser.add_argument('-t', '--talker', action='store_true', default=False, dest='talker',
                        help='Flag used to specify the server is will send request to encrpyt data')

    parser.add_argument('-l', '--listener', action='store_true', default=False, dest='listener',
                        help='Flag used to specify the server is will send request to encrpyt data')

    return parser.parse_args()

class ClientThread(threading.Thread):
    def __init__(self, client_address, clientsocket):
        """
        Default constructor or class handling client socket thread
        """
        threading.Thread.__init__(self)
        self.clientd = clientsocket
        self.protocol = None
        self.length = None
        self.buffer = None

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
            break

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

            print(self.buffer)
            print(len(self.buffer))

            """
                Need to validate contents of the buffer
            """
            if (self.is_valid_contents()):
                print('Valid contents in request')
                # TODO: Need to send response
            else:
                print('Invalid contents in request')
                # TODO: Need to close connection

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
        if self.buffer == '{}':
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

def main():
    """
        Main Entrance of the Server
    """
    args  = handle_arguments()

    """
        Create an INET, STREAMing socket
    """
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    """
        Bind socket to a public host and port
    """
    serversocket.bind((socket.gethostname(), args.PORT))

    serversocket.listen(MAX_CONNECTIONS)

    """
        Main loop of web server
    """
    while True:
        # accept connection
        (clientsocket, address) = serversocket.accept()

        """
            Now handle something with the clientsocket
        """
        ct = ClientThread(address, clientsocket)
        ct.run()




if __name__ == '__main__':
    main()