#!/usr/bin/env python3
"""
    Script to handle server socket implementation for CSE 234 Project
"""
import argparse


def handle_arguments():
    """
    Function used to set and handle arguments
    """
    parser = argparse.ArgumentParser(description='Server Accepting and Sending Encrypt/Decrypt Request')
    parser.add_argument('integers', metavar='port', type=int, nargs='+',
                        help='Port for server to listen on')

    parser.add_argument('-t', '--talker', dest='talker',
                        help='Flag used to specify the server is will send request to encrpyt data')

    parser.add_argument('-l', '--listener', dest='listener',
                        help='Flag used to specify the server is will send request to encrpyt data')

    return parser.parse_args()


def main():
    """
        Main Entrance of the Server
    """
    args  = handle_arguments()

if __name__ == '__main__':
    main()