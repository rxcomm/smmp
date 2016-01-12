#!/usr/bin/env python
"""A simple echo server for smmptor that uses tor to hide metadata.

Copyright (C) 2016 by David R. Andersen <k0rx@RXcomm.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

import binascii
import threading
import socket
import sys
import stem.process
from stem.control import Controller
from stem.util import term
from contextlib import contextmanager

TOR_SERVER_PORT = 9054
TOR_SERVER_CONTROL_PORT = 9055
TOR_CONTROL_PASSWORD = 'smmptor'
TOR_CONTROL_HASHED_PASSWORD = \
    '16:267620CD1275C7E760CB387FD2B32CD1CC4AC3734FA2FCCC92E50EBE49'
GROUPSIZE = 10 # should be >= number in group

@contextmanager
def socketcontext(*args, **kwargs):
    """localhost socket for connecting to hidden service"""

    soc = socket.socket(*args, **kwargs)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    yield soc
    soc.close()

def tor(port, controlport, tor_dir):
    """tor instance"""

    tor_process = stem.process.launch_tor_with_config(
        tor_cmd = 'tor',
        config = {
                  'ControlPort': str(controlport),
                  'SocksPort' : str(port),
                  'Log' : ['NOTICE stdout',
                                  'ERR file /tmp/tor_error_log',
                          ],
                  'DataDirectory' : tor_dir,
                  'HashedControlPassword' : TOR_CONTROL_HASHED_PASSWORD,
                 },
        completion_percent = 100,
        take_ownership = True,
        timeout = 90,
        init_msg_handler = print_bootstrap_lines,
        )
    return tor_process

def print_bootstrap_lines(line):
    """print tor bootstrap info in nice red font"""

    if 'Bootstrapped ' in line:
        print term.format(line, term.Color.RED)

def hiddenService():
    """hidden service instance"""

    PORT = 50000
    HOST = '127.0.0.1'
    hidden_svc_dir = 'tor.hs/'

    print ' * Getting controller'
    controller = Controller.from_port(address='127.0.0.1',
                                      port=TOR_SERVER_CONTROL_PORT
                                     )
    try:
        controller.authenticate(password=TOR_CONTROL_PASSWORD),
        controller.set_options([
            ('HiddenServiceDir', hidden_svc_dir),
            ('HiddenServicePort', '50000 %s:%s' % (HOST, str(PORT))),
            ])
        svc_name = open(hidden_svc_dir + 'hostname', 'r').read().strip()
        print ' * Created onion server: %s' % svc_name
    except Exception as e:
        print e
    return controller

def receiveData(client, address, index):
    """receive data thread"""

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
                    item.send('SYSMSG' + 'Disconnection: only ' + \
                              str(len(client_list)) + ' users connected\nEOP'
                             )
                print str(address) + ' disconnected'
                sys.exit()
            data = data + rcv
        data_list = data.split('EOP')
        for data in data_list:
            if data != '':
                if LOGTRAFFIC:
                    with open('server.traffic.log', 'a') as f:
                        f.write(binascii.b2a_base64(data[3:]))
                for i, item in client_list.iteritems():
                    try:
                        if (data[:3] != '998' and client != item) and \
                           (data[:3] == '999' or int(data[:3]) == i):
                            item.send(data[3:] + 'EOP')
                    except ValueError:
                        pass

if __name__ == '__main__':
    ans = raw_input('Keep a log of the (encrypted) traffic? y/N ')
    if ans == 'y' or ans == 'Y' or ans == 'yes':
        LOGTRAFFIC = True
        print '(Encrypted) traffic will be logged to server.traffic.log'
    else:
        LOGTRAFFIC = False
    tor_process = tor(TOR_SERVER_PORT, TOR_SERVER_CONTROL_PORT, 'tor.server')
    hs = hiddenService()
    with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 50000))
        s.listen(GROUPSIZE)
        client_list = {}
        client_list_index = 0
        address_list = []
        try:
            while True:
                client, address = s.accept()
                data = ''
                while data[-5:] != 'START':
                    rcv = client.recv(1024)
                    data = data + rcv
                my_index = int(data[:-5])
                client_list[my_index] = client
                address_list = address_list + [address]
                threading.Thread(target=receiveData, args=(client,
                                                           address, my_index
                                                          )).start()
                print str(my_index) + ': ' +str(address) + ' connected'
        except KeyboardInterrupt:
            print 'Server stopped'
