#!/usr/bin/env python

"""
A simple server monitor for axochat
"""

import binascii
import socket
import sys

HOST = '0.0.0.0'
PORT = 50000
BACKLOG = 5

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.connect((HOST,PORT))

try:
    while True:
        data = s.recv(1024)
        if not data:
            print 'Disconnected'
            sys.exit()
        print binascii.b2a_base64(data)
except KeyboardInterrupt:
    print 'Disconnected'
