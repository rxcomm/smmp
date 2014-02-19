#!/usr/bin/env python

import binascii
import socket
import threading
import sys
import curses
from curses.textpad import Textbox
from random import randint
from contextlib import contextmanager
from time import sleep
from smmp import Participant, Organizer, BummerUndecryptable

"""
Standalone chat script using AES256 encryption with Axolotl ratchet for
key management.

Usage:
1. Create databases using:
     axochat.py -g
   for both nicks in the conversation

2. One side starts the server with:
     axochat.py -s

3. The other side connects the client to the server with:
     axochat.py -c

4. .quit at the chat prompt will quit (don't forget the "dot")

Port 50000 is the default port, but you can choose your own port as well.

Be sure to edit the getPasswd() method to return your password. You can
hard code it or get it from e.g. a keyring. It just has to match the password
you used when creating the database.

Axochat requires the Axolotl module at https://github.com/rxcomm/pyaxo

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
def organizer(group_name):
    a = Organizer(group_name)
    yield a

@contextmanager
def participant(group_name):
    a = Participant(group_name)
    yield a

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
    curses.init_pair(3, 2, -1)
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

def receiveThread(sock, mypart, stdscr, input_win, output_win):
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
                    output_win.addstr(data[6:])
                else:
                    output_win.addstr(mypart.decrypt(data))
        input_win.move(cursory, cursorx)
        input_win.cursyncup()
        input_win.noutrefresh()
        output_win.noutrefresh()
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
    t = threading.Thread(target=receiveThread, args=(sock,mypart,stdscr,input_win,output_win))
    t.daemon = True
    t.start()
    try:
        while True:
            lock.acquire()
            data = textpad.edit(validator)
            if myname+':> .quit' in data:
                closeWindows(stdscr)
                ans = raw_input('Save the state? Y/n ')
                if ans != 'n' and ans != 'N':
                    saveState(mypart)
                sys.exit()
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
                sock.send(mypart.encrypt(data) + 'EOP')
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
    with open('chatdata_'+str(mypart.state['my_index'])+'.dat', 'w') as f:
        f.write(binascii.b2a_base64(mypart.state['HK']))
        f.write(binascii.b2a_base64(mypart.state['MK']))
        f.write(binascii.b2a_base64(mypart.state['NHK']))
        f.write(binascii.b2a_base64(mypart.state['RK']))
        f.write(binascii.b2a_base64(mypart.state['v']))
        f.write(mypart.state['group_name']+'\n')
        f.write(str(mypart.state['my_index'])+'\n')
        f.write(str(mypart.group_size)+'\n')
        for key, item in mypart.state['R'].iteritems():
            f.write(binascii.b2a_base64(item))

def loadState(mypart):
    file_name = raw_input('What file do you want to load? ')
    with open(file_name, 'r') as f:
        data = f.read()
        data_list = data.split()
        mypart.state['HK'] = binascii.a2b_base64(data_list[0])
        mypart.state['MK'] = binascii.a2b_base64(data_list[1])
        mypart.state['NHK'] = binascii.a2b_base64(data_list[2])
        mypart.state['RK'] = binascii.a2b_base64(data_list[3])
        mypart.state['v'] = binascii.a2b_base64(data_list[4])
        mypart.state['group_name'] = data_list[5]
        mypart.state['my_index'] = int(data_list[6])
        mypart.group_size = int(data_list[7])
        mypart.state['R'] = {}
        for i in range(mypart.group_size):
            mypart.state['R'][i] = binascii.a2b_base64(data_list[8+i])



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

    R = {}
    HOST = raw_input('Enter the server: ')
    print 'Connecting to ' + HOST + '...'
    with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        ans = raw_input('Do you want to load a state? y/N ')
        if ans == 'y':
            with participant('dummy') as mypart:
                loadState(mypart)
                myname = raw_input('What is your name? ')
                chatThread(s, mypart, myname)
                exit()

        group_name = raw_input('What is the group name? ')
        num_users = int(raw_input('Input total number of participants (including you): '))
        with participant(group_name) as mypart:
            ans = raw_input('Are you the group organizer? y/N ')
            if ans == 'y':
                with organizer(group_name) as org:
                    useridkeylist = {}
                    userhskeylist = {}
                    userrtkeylist = {}
                    for i in range(1, num_users):
                        useridkeylist[i] = binascii.a2b_base64(raw_input('User '+str(i)+' ID key: '))
                        userhskeylist[i] = binascii.a2b_base64(raw_input('User '+str(i)+' handshake key: '))
                        userrtkeylist[i] = binascii.a2b_base64(raw_input('User '+str(i)+' ratchet key: '))
                    useridkeylist[0] = mypart.identityPKey
                    userhskeylist[0] = mypart.handshakePKey
                    userrtkeylist[0] = mypart.ratchetPKey
                    org.initState(group_name, useridkeylist, userhskeylist, userrtkeylist, 0)
                    print 'The following items should be passed securely to all participants'
                    print 'The group identity key: '+binascii.b2a_base64(org.state['pU'])
                    print 'The group handshake key: '+binascii.b2a_base64(org.state['pW'])
                    print 'The group ratchet key: '+binascii.b2a_base64(org.state['v'])
                    print 'The participant ratchet keys are:'
                    for key, item in org.state['R'].iteritems():
                        print 'Participant '+str(key)+' ratchet key: '+binascii.b2a_base64(item)
                    print 'The G value for each user should be passed securely to that user'
                    for key, item in org.G.iteritems():
                        if key != 0:
                            print 'G for user '+str(key)+' is: '+ binascii.b2a_base64(item)
                    pU = org.state['pU']
                    pW = org.state['pW']
                    G0 = org.G[0]
                    v = org.state['v']
                mypart.initState(group_name, pU, pW, userrtkeylist, num_users, G0, v, my_index= 0)
                ans = raw_input('When everyone has the group data, hit <RETURN>')
            else:
                print 'Your identity key is '+binascii.b2a_base64(mypart.identityPKey)
                print 'Your handshake key is '+binascii.b2a_base64(mypart.handshakePKey)
                print 'Your ratchet key is '+binascii.b2a_base64(mypart.ratchetPKey)
                print 'The following required information will be provided by the group organizer'
                my_index = int(raw_input('Input your user number: '))
                group_identityPKey = binascii.a2b_base64(raw_input('Input the group identity key: '))
                group_handshakePKey = binascii.a2b_base64(raw_input('Input the group handshake key: '))
                group_ratchetPKey = binascii.a2b_base64(raw_input('Input the group ratchet key: '))
                G = binascii.a2b_base64(raw_input('Input G: '))
                R[my_index] = mypart.ratchetPKey
                for i in range(num_users):
                    if i != my_index:
                        R[i] = binascii.a2b_base64(raw_input('Input user '+str(i)+'\'s ratchet key: '))
                mypart.initState(group_name, group_identityPKey, group_handshakePKey, R, num_users, G, group_ratchetPKey, my_index=my_index)



            myname = raw_input('What is your name? ')
            saveState(mypart)
            chatThread(s, mypart, myname)

