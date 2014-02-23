#!/usr/bin/env python

"""
A simple echo server for axochat
"""

import binascii
import socket
import threading
import sys
from time import time

HOST = '0.0.0.0'
PORT = 50000
BACKLOG = 10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST,PORT))
s.listen(BACKLOG)
client_list = []
address_list = []

def receiveData(client, address):
    global client_list
    global address_list
    for item in client_list:
        item.send('SYSMSG' + str(len(client_list)) + ' users connected\nEOP')
    while True:
        data = client.recv(1024)
        if not data:
            client_list.remove(client)
            address_list.remove(address)
            for item in client_list:
                item.send('SYSMSG' + 'Disconnection: only ' + str(len(client_list)) + ' users connected\nEOP')
            print str(address) + ' disconnected'
            with open('server.log', 'a') as f:
                f.write('client disconnected ' + address[0] + ' ' + str(address[1]) + ' ' + str(int(time())) + '\n')
            sys.exit()
        else:
            with open('server.data.log', 'a') as f:
                f.write(binascii.b2a_base64(data))
            for item in client_list:
                if item != client:
                    item.send(data)

try:
    while True:
        client, address = s.accept()
        client_list = client_list + [client]
        address_list = address_list + [address]
        threading.Thread(target=receiveData,args=(client,address)).start()
        print str(address) + ' connected'
        #with open('server.log', 'a') as f:
        #    f.write('added new client ' + address[0] + ' ' + str(address[1]) + ' ' + str(int(time())) + '\n')
except KeyboardInterrupt:
    print 'Server stopped'
