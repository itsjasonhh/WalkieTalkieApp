#!/usr/bin/env python3
"""
    Script to handle server / client socket implementation for CSE 234 Project
"""
import argparse
from Crypto.PublicKey import RSA
from server.server import Server
from client.client import Client

SERVER = '127.0.0.1'
PUB_KEY_PATH = 'keylib/pubkey.pem'
PRI_KEY_PATH = 'keylib/key.pem'

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

def main():
    """
        Main Entrance of the Server
    """
    args  = handle_arguments()


    if (args.listener and args.talker):
        print('You can either be a listener or talker, not both!')
        exit(1)

    if (not args.listener and not args.talker):
        """
        Default to being a 'listener' If user does not specify
        """
        args.listener = True

    """
        Need to load RSA private and public keys
    """
    f = open(PRI_KEY_PATH, 'r')
    key = RSA.import_key(f.read())
    f.close()

    f = open(PUB_KEY_PATH, 'r')
    pubkey = RSA.import_key(f.read())
    f.close()


    if args.listener:
        """
            We are the server and we are open to accepting requests
        """
        server = Server('', args.PORT)
        server.init()
        server.run()

    if (args.talker):
        """
            We are a client and we want to send a request
        """
        client = Client(SERVER, args.PORT, public_key, private_key)
        client.init()
        client.run()

if __name__ == '__main__':
    main()
