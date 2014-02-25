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
client_list = {}
client_list_index = 0
address_list = []

def receiveData(client, address, index):
    global client_list
    global address_list
    for i, item in client_list.iteritems():
        item.send('SYSMSG' + str(len(client_list)) + ' users connected\nEOP')
    while True:
        data = ''
        while data[-3:] != 'EOP':
            rcv = client.recv(1024)
            if not rcv:
                del client_list[index]
                address_list.remove(address)
                for i, item in client_list.iteritems():
                    item.send('SYSMSG' + 'Disconnection: only ' + str(len(client_list)) + ' users connected\nEOP')
                print str(address) + ' disconnected'
                sys.exit()
            data = data + rcv
        data_list = data.split('EOP')
        for data in data_list:
            if data != '':
                for i, item in client_list.iteritems():
                    if (data[:3] != '998' and client != item) and (data[:3] == '999' or int(data[:3]) == i):
                        item.send(data[3:] + 'EOP')

try:
    while True:
        client, address = s.accept()
        if len(client_list) == 0:
            client_list_index = 0
        client_list[client_list_index] = client
        address_list = address_list + [address]
        threading.Thread(target=receiveData,args=(client,address,client_list_index)).start()
        print str(address) + ' connected'
        client_list_index += 1
except KeyboardInterrupt:
    print 'Server stopped'
