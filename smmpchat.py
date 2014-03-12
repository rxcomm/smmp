#!/usr/bin/env python

import re
import binascii
import socket
import threading
import sys
import curses
import gnupg
import hmac
import hashlib
from curses.textpad import Textbox
from random import randint
from contextlib import contextmanager
from time import sleep
from smmp import Participant, BummerUndecryptable, BadHMAC, BadDIGEST
from StringIO import StringIO
from getpass import getpass
from bd import BD

"""
Standalone multi-party chat script using AES256 encryption with
SMMP ratchet for key management.

Usage:
1. Start the chat script with
      ./smmpchat.py
   One person will need to serve as Organizer. Once key-agreement
   has been reached the Organizer role is abandoned, and all users
   are peers.

2. All exchange of data during the key-agreement phase may be done
   over an insecure medium.

3. .quit at the chat prompt will quit (don't forget the "dot")

4. If you lose synchronization with a user (Undecryptable message error),
   hit <RETURN> and the system should re-sync you. You can also resync
   by typing .resync at the chat prompt.

5. If you receive a Bad HMAC error, either 1) you are badly out of sync
   and will need to perform a new key-agreement step, or 2) Somebody
   else is spamming your port with garbage packets. Neither is good.

6. If you have the means to distribute keys securely to all users, you can
   use the gendata.py utility to generate a keyset and skip the formal
   key agreement process.

Port 50000 is the default port, but you can choose your own port as well.

smmpchat requires the SMMP module.

Copyright (C) 2014 by David R. Andersen <k0rx@RXcomm.net>

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

@contextmanager
def socketcontext(*args, **kwargs):
    s = socket.socket(*args, **kwargs)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    yield s
    s.close()

@contextmanager
def participant(group_name, group_size, my_index):
    a = Participant(group_name, group_size, my_index)
    yield a

@contextmanager
def encFile(file_name, passphrase):
    a = StringIO()
    yield a
    KEYRING = './keyring.gpg'
    SECRET_KEYRING = './secring.gpg'
    GPGBINARY = 'gpg'
    gpg = gnupg.GPG(gnupghome='.', gpgbinary=GPGBINARY, keyring=KEYRING,
                    secret_keyring=SECRET_KEYRING, options=['--throw-keyids',
                    '--personal-digest-preferences=sha256','--s2k-digest-algo=sha256'])
    gpg.encoding = 'utf-8'
    ciphertext = gpg.encrypt(a.getvalue(), recipients=None, symmetric='AES256',
                             armor=False, always_trust=True, passphrase=passphrase)
    a.close()
    with open(file_name, 'wb') as f:
        f.write(ciphertext.data)

@contextmanager
def decFile(file_name, passphrase):
    KEYRING = './keyring.gpg'
    SECRET_KEYRING = './secring.gpg'
    GPGBINARY = 'gpg'
    gpg = gnupg.GPG(gnupghome='.', gpgbinary=GPGBINARY, keyring=KEYRING,
                    secret_keyring=SECRET_KEYRING, options=['--throw-keyids',
                    '--personal-digest-preferences=sha256','--s2k-digest-algo=sha256'])
    gpg.encoding = 'utf-8'
    with open(file_name, 'rb') as f:
        ciphertext = f.read()
    plaintext = gpg.decrypt(ciphertext, passphrase=passphrase, always_trust=True)
    a = StringIO(plaintext)
    a.seek(0)
    yield a
    a.close()

class _Textbox(Textbox):
    """
    curses.textpad.Textbox requires users to ^g on completion, which is sort
    of annoying for an interactive chat client such as this, which typically only
    reuquires an enter. This subclass fixes this problem by signalling completion
    on Enter as well as ^g. Also, map <Backspace> key to ^h.
    """
    def __init__(*args, **kwargs):
        Textbox.__init__(*args, **kwargs)

    def do_command(self, ch):
        if ch == 10: # Enter
            return 0
        if ch == 127: # Enter
            return 8
        return Textbox.do_command(self, ch)

def validator(ch):
    """
    Update screen if necessary and release the lock so receiveThread can run
    """
    global screen_needs_update
    try:
        if screen_needs_update:
            curses.doupdate()
            screen_needs_update = False
        return ch
    finally:
        lock.release()
        sleep(0.01) # let receiveThread in if necessary
        lock.acquire()

def windows():
    stdscr = curses.initscr()
    curses.noecho()
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_CYAN, -1)
    curses.init_pair(3, curses.COLOR_GREEN, -1)
    curses.cbreak()
    curses.curs_set(1)
    (sizey, sizex) = stdscr.getmaxyx()
    input_win = curses.newwin(8, sizex, sizey-8, 0)
    output_win = curses.newwin(sizey-9, sizex, 1, 0)
    title_win = curses.newwin(1, sizex, 0, 0)
    input_win.idlok(1)
    input_win.scrollok(1)
    input_win.nodelay(1)
    input_win.leaveok(0)
    input_win.timeout(100)
    input_win.attron(curses.color_pair(3))
    output_win.idlok(1)
    output_win.scrollok(1)
    output_win.leaveok(0)
    title_win.idlok(1)
    title_win.scrollok(1)
    title_win.leaveok(0)
    return stdscr, input_win, output_win, title_win

def closeWindows(stdscr):
    curses.nocbreak()
    stdscr.keypad(0)
    curses.echo()
    curses.endwin()

def usage():
    print 'Usage: ' + sys.argv[0] + ' -(s,c,g)'
    print ' -s: start a chat in server mode'
    print ' -c: start a chat in client mode'
    print ' -g: generate a key database for a nick'
    exit()

def s2l(s):
    return long(binascii.hexlify(s), 16)

def l2s(n):
    num = '%x' % n
    if len(num) % 2:
        num = '0' + num
    return binascii.unhexlify(num)

def receiveThread(sock, mypart, stdscr, input_win, output_win, title_win):
    global screen_needs_update
    while True:
        data = ''
        while data[-3:] != 'EOP':
            rcv = sock.recv(1024)
            if not rcv:
                input_win.move(0, 0)
                input_win.addstr('Disconnected - Ctrl-C to exit!')
                input_win.refresh()
                sys.exit()
            data = data + rcv
        data_list = data.split('EOP')
        lock.acquire()
        (cursory, cursorx) = input_win.getyx()
        for data in data_list:
            if data != '':
                if data[:6] == 'SYSMSG':
                    title_win.clear()
                    title_win.addstr(0, 0, 'Group: ', curses.color_pair(2))
                    title_win.addstr(mypart.state['group_name'], curses.color_pair(2))
                    title_win.addstr(' | ', curses.color_pair(3))
                    if int(re.search('\d+', data[6:]).group()) == mypart.group_size:
                        clr = 2
                    else:
                        clr = 1
                    title_win.addstr('Status: ', curses.color_pair(clr))
                    title_win.addstr(data[6:].strip(), curses.color_pair(clr))
                    title_win.addstr(' | ', curses.color_pair(3))
                    title_win.addstr('Users in group: '+str(mypart.group_size), curses.color_pair(clr))
                else:
                    try:
                        msg = mypart.decrypt(data)
                        if msg[:31] == 'Ratchet resync message received':
                            output_win.addstr(msg, curses.color_pair(1))
                        else:
                            output_win.addstr(msg)
                    except (BummerUndecryptable, TypeError):
                        mypart.resync_required = True
                        output_win.addstr('Undecryptable message\n', curses.color_pair(1))
                    except BadHMAC:
                        output_win.addstr('Bad HMAC\n', curses.color_pair(1))
        input_win.move(cursory, cursorx)
        input_win.cursyncup()
        input_win.noutrefresh()
        output_win.noutrefresh()
        title_win.noutrefresh()
        screen_needs_update = True
        lock.release()

def chatThread(sock, mypart, myname):
    global screen_needs_update
    stdscr, input_win, output_win, title_win = windows()
    title_win.addstr('Group: ', curses.color_pair(3))
    title_win.addstr(mypart.state['group_name'])
    title_win.noutrefresh()
    input_win.addstr(0, 0, myname+':> ')
    textpad = _Textbox(input_win, insert_mode=True)
    textpad.stripspaces = True
    delay = randint(1, mypart.group_size + 10)
    t = threading.Thread(target=receiveThread, args=(sock,mypart,stdscr,input_win,output_win,title_win))
    t.daemon = True
    t.start()
    try:
        while True:
            lock.acquire()
            data = textpad.edit(validator)
            if myname+':> .resync' in data or mypart.resync_required:
                lock.release()
                mypart.resync_required = True
                msg = mypart.resyncSend(sock)
                lock.acquire()
                input_win.clear()
                input_win.addstr(myname+':> ')
                output_win.addstr(msg + '\n', curses.color_pair(1))
                output_win.noutrefresh()
                input_win.move(0, len(myname) +3)
                input_win.cursyncup()
                input_win.noutrefresh()
                screen_needs_update = True
                lock.release()
            elif myname+':> .quit' in data:
                closeWindows(stdscr)
                ans = raw_input('Save the state? Y/n ')
                if ans != 'n' and ans != 'N':
                    saveState(mypart)
                sys.exit()
            else:
                input_win.clear()
                input_win.addstr(myname+':> ')
                output_win.addstr(data.replace('\n', '') + '\n', curses.color_pair(3))
                output_win.noutrefresh()
                input_win.move(0, len(myname) +3)
                input_win.cursyncup()
                input_win.noutrefresh()
                screen_needs_update = True
                data = data.replace('\n', '') + '\n'
                try:
                    ciphertexts = mypart.encrypt(data)
                    if type(ciphertexts) is dict:
                        for i, message in ciphertexts.iteritems():
                            sock.send(message + 'EOP')
                    else:
                        sock.send(ciphertexts + 'EOP')
                except socket.error:
                    input_win.addstr('Disconnected')
                    input_win.refresh()
                    closeWindows(stdscr)
                    sys.exit()
                lock.release()
    except KeyboardInterrupt:
        closeWindows(stdscr)
        ans = raw_input('Save the state? Y/n ')
        if ans != 'n' and ans != 'N':
            saveState(mypart)

def saveState(mypart):
    file_name = raw_input('What file do you want to save the data in? ')
    passphrase=''
    passphrase1='1'
    while passphrase != passphrase1:
        passphrase = getpass('What is the passphrase for the file: ')
        passphrase1 = getpass('Repeat: ')
        if passphrase != passphrase1:
            print 'Passphrases did not match'
    with encFile(file_name, passphrase) as f:
        f.write(binascii.b2a_base64(mypart.state['HK']))
        f.write(binascii.b2a_base64(mypart.state['MK']))
        f.write(binascii.b2a_base64(mypart.state['RK']))
        f.write(binascii.b2a_base64(mypart.state['v']))
        f.write(mypart.state['group_name']+'\n')
        f.write(str(mypart.state['my_index'])+'\n')
        f.write(str(mypart.group_size)+'\n')
        resync_required = '1' if mypart.resync_required else '0'
        f.write(resync_required+'\n')
        f.write(binascii.b2a_base64(mypart.ratchetKey))
        f.write(binascii.b2a_base64(mypart.state['initr']))
        f.write(binascii.b2a_base64(mypart.state['digest']))
        for key, item in mypart.state['initpubR'].iteritems():
            f.write(binascii.b2a_base64(item))
        for key, item in mypart.state['R'].iteritems():
            f.write(binascii.b2a_base64(item))

def loadState(mypart):
    file_name = raw_input('What file do you want to load? ')
    passphrase = getpass('What is the passphrase for the file? ')
    with decFile(file_name, passphrase) as f:
        data = f.read()
        data_list = data.split()
        mypart.state['HK'] = binascii.a2b_base64(data_list[0])
        mypart.state['MK'] = binascii.a2b_base64(data_list[1])
        mypart.state['RK'] = binascii.a2b_base64(data_list[2])
        mypart.state['v'] = binascii.a2b_base64(data_list[3])
        mypart.state['group_name'] = data_list[4]
        mypart.state['my_index'] = int(data_list[5])
        mypart.group_size = int(data_list[6])
        resync_required = data_list[7]
        mypart.resync_required = True if resync_required == '1' else False
        mypart.ratchetKey = binascii.a2b_base64(data_list[8])
        mypart.state['initr'] = binascii.a2b_base64(data_list[9])
        mypart.state['digest'] = binascii.a2b_base64(data_list[10])
        mypart.state['R'] = {}
        mypart.state['initpubR'] = {}
        for i in range(mypart.group_size):
            mypart.state['initpubR'][i] = binascii.a2b_base64(data_list[11+i])
        for i in range(mypart.group_size):
            mypart.state['R'][i] = binascii.a2b_base64(data_list[11+mypart.group_size+i])

if __name__ == '__main__':

    lock = threading.Lock()
    screen_needs_update = False
    HOST = ''
    while True:
        try:
            PORT = raw_input('TCP port (1 for random choice, 50000 is default): ')
            PORT = int(PORT)
            break
        except ValueError:
            PORT = 50000
            break
    if PORT >= 1025 and PORT <= 65535:
        pass
    elif PORT == 1:
        PORT = 1025 + randint(0, 64510)
        print 'PORT is ' + str(PORT)

    k = {}
    x = {}
    R = {}
    HOST = raw_input('Enter the server: ')

    ans = raw_input('Do you want to load a state? y/N ')
    if ans == 'y':
        with participant('dummy', 0, 0) as mypart:
            loadState(mypart)
            myname = raw_input('What is your name? ')
            print 'Connecting to ' + HOST + '...'
            with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.send(str(mypart.state['my_index']).zfill(3) + 'START')
                chatThread(s, mypart, myname)
            exit()

    group_name = raw_input('What is the group name? ')
    num_users = int(raw_input('Input total number of participants (including you): '))
    my_index = int(raw_input('Input your participant number: '))
    with participant(group_name, num_users, my_index) as mypart:
        print 'Your public identity key is: '+binascii.b2a_base64(mypart.identityPKey)
        #print 'Your public handshake key is: '+binascii.b2a_base64(l2s(mypart.bd.pubKey))
        print 'Your public ratchet key is: '+binascii.b2a_base64(mypart.ratchetPKey)
        identityKeys = {}
        k = {}
        R = {}
        signatures = {}
        identityKeys[my_index] = mypart.identityPKey
        k[my_index] = mypart.bd.pubKey
        R[my_index] = mypart.ratchetPKey
        for i in range(num_users):
            if i != my_index:
                identityKeys[i] = binascii.a2b_base64(raw_input('Input user '+str(i)+'\'s public identity key: '))
                R[i] = binascii.a2b_base64(raw_input('Input user '+str(i)+'\'s public ratchet key: '))
        for i in range(num_users):
            if i != my_index:
                mackey = mypart.genDH(mypart.identityKey, R[i]) + \
                         mypart.genDH(mypart.ratchetKey, identityKeys[i]) + \
                         mypart.genDH(mypart.ratchetKey, R[i])
                mackey = hashlib.sha256(mackey).digest()
                mac = hmac.new(mackey, str(k[my_index]), hashlib.sha256).digest()
                print 'Send this signed public handshake key to user '+str(i)+': '+binascii.b2a_base64(l2s(k[my_index])+mac)
        for i in range(num_users):
            if i != my_index:
                k[i] = raw_input('Input user '+str(i)+'\'s signed public handshake key: ')
        mypart.initState(group_name, identityKeys, k, R)

    myname = raw_input('What is your name? ')
    print 'Connecting to ' + HOST + '...'
    with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.send(str(mypart.state['my_index']).zfill(3) + 'START')
        chatThread(s, mypart, myname)

