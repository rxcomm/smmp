#!/usr/bin/env python

from smmp import Participant, BummerUndecryptable, BadHMAC
from contextlib import contextmanager
from curve25519 import keys
from passlib.utils.pbkdf2 import pbkdf2
from random import randint
from time import sleep
from copy import deepcopy
import os
import binascii
import hashlib
import gnupg
from StringIO import StringIO

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

def strxor(s0, s1):
    l = [chr(ord(a)^ord(b)) for a,b in zip(s0, s1)]
    return ''.join (l)

def hilite(text, c=False):
    attr = []
    if c:
        attr.append('41')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), text)

def loadState(mypart, num):
    file_name = 'ex_data/example'+str(num)+'.dat'
    passphrase = '1'
    with decFile(file_name, passphrase) as f:
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
        resync_required = data_list[8]
        mypart.resync_required = True if resync_required == '1' else False
        mypart.ratchetKey = binascii.a2b_base64(data_list[9])
        mypart.state['initr'] = binascii.a2b_base64(data_list[10])
        mypart.state['digest'] = binascii.a2b_base64(data_list[11])
        mypart.state['R'] = {}
        mypart.state['initpubR'] = {}
        for i in range(mypart.group_size):
            mypart.state['initpubR'][i] = binascii.a2b_base64(data_list[12+i])
        for i in range(mypart.group_size):
            mypart.state['R'][i] = binascii.a2b_base64(data_list[12+mypart.group_size+i])

def saveState(mypart, num):
    file_name = 'ex_data/example'+str(num)+'.dat'
    passphrase = '1'
    with encFile(file_name, passphrase) as f:
        f.write(binascii.b2a_base64(mypart.state['HK']))
        f.write(binascii.b2a_base64(mypart.state['MK']))
        f.write(binascii.b2a_base64(mypart.state['NHK']))
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

p0 = Participant('my cool group name', 8, 0)
p1 = Participant('my cool group name', 8, 1)
p2 = Participant('my cool group name', 8, 2)
p3 = Participant('my cool group name', 8, 3)
p4 = Participant('my cool group name', 8, 4)
p5 = Participant('my cool group name', 8, 5)
p6 = Participant('my cool group name', 8, 6)
p7 = Participant('my cool group name', 8, 7)

try:
    loadState(p0, 0)
    loadState(p1, 1)
    loadState(p2, 2)
    loadState(p3, 3)
    loadState(p4, 4)
    loadState(p5, 5)
    loadState(p6, 6)
    loadState(p7, 7)
except IOError:
    print 'No state files available - generate them with gendata.py'
    exit()

participants = ('p0', 'p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7')
data_old = deepcopy(p0.state)
while True:
    try:
        os.system('clear')
        print '\x1b[;32m Ratchet Keys\x1b[0m'
        print '--------------------------------------------------'
        chg = False
        for i in range(len(p0.state['R'])):
            if p0.state['R'][i] != data_old['R'][i]: chg=True
            print ' P'+str(i)+': '+hilite(binascii.b2a_base64(p0.state['R'][i]).strip(), chg)
            chg = False
        print '--------------------------------------------------'
        print
        print '\x1b[;32m State\x1b[0m'
        print '--------------------------------------------------'
        for key in sorted(p0.state):
            if key == 'R':
                pass
            else:
                if p0.state[key] != data_old[key]: chg = True
                if key == 'group_name':
                    pass
                elif key == 'my_index':
                    pass
                elif key == 'initr':
                    pass
                elif key == 'initpubR':
                    pass
                elif key == 'digest':
                    print 'dgt: '+hilite(binascii.b2a_base64(p0.state[key]).strip(), chg)
                else:
                    print '{:>3}'.format(key)+': '+hilite(binascii.b2a_base64(p0.state[key]).strip(), chg)
                chg = False
        print '--------------------------------------------------'

        data_old = deepcopy(p0.state)

        encrypter = randint(0,7)

        resync = randint(0,3)
        if resync == 0:
            exec('vnew, pVnew = p' + str(encrypter) + '.genKey()')
            exec('rnew, pRnew = p' + str(encrypter) + '.genKey()')
            exec('v = hashlib.sha256(p' + str(encrypter) + '.state["v"] + vnew).digest()')
            exec('p' + str(encrypter) + '.state["initr"] = deepcopy(rnew)')
            for i in range(len(participants)):
                exec('p' + str(i) + '.state["initpubR"][encrypter] = deepcopy(pRnew)')
            DHR = ''
            for i in range(len(participants)):
                DHR = DHR + p0.state['initpubR'][i]
            DHR = hashlib.sha256(DHR).digest()
            exec('RK = hashlib.sha256(DHR + p' + str(encrypter) + '.genDH(v, DHR)).digest()')
            HK = pbkdf2(RK, b'\x01', 10, prf='hmac-sha256')
            NHK = pbkdf2(RK, b'\x02', 10, prf='hmac-sha256')
            MK = pbkdf2(RK, b'\x03', 10, prf='hmac-sha256')
            for i in range(len(participants)):
                exec('p' + str(i) + '.ratchetKey = deepcopy(p' + str(i) + '.state["initr"])')
                exec('p' + str(i) + '.state["v"] = deepcopy(v)')
                exec('p' + str(i) + '.state["R"] = deepcopy(p' + str(i) + '.state["initpubR"])')
                exec('p' + str(i) + '.state["RK"] = deepcopy(RK)')
                exec('p' + str(i) + '.state["HK"] = deepcopy(HK)')
                exec('p' + str(i) + '.state["NHK"] = deepcopy(NHK)')
                exec('p' + str(i) + '.state["MK"] = deepcopy(MK)')
            # exec() doesn't like null bytes
            p0.state['digest'] = '\x00' * 32
            p1.state['digest'] = '\x00' * 32
            p2.state['digest'] = '\x00' * 32
            p3.state['digest'] = '\x00' * 32
            p4.state['digest'] = '\x00' * 32
            p5.state['digest'] = '\x00' * 32
            p6.state['digest'] = '\x00' * 32
            p7.state['digest'] = '\x00' * 32


        print
        print '\x1b[;32m Message encrypted by P'+str(encrypter)+'\x1b[0m'
        print '---------------------------------------------------------'
        command = 'ciphertexts = p'+str(encrypter)+'.encrypt("This message was encrypted by P" + str(encrypter))'
        exec(command)

        for i in range(len(participants)):
            try_twice = randint(0,9)
            second_decryption = False
            try:
                try:
                    print 'P'+str(i)+': '+eval(participants[i]+'.decrypt(ciphertexts[i][3:])') + ' and decrypted by P' + str(i)
                except KeyError:
                    raise BummerUndecryptable
                if try_twice == 0:
                    second_decryption = True
                    print ' ' + eval(participants[i]+'.decrypt(ciphertexts[i][3:])')
            except (BummerUndecryptable, BadHMAC):
                if not second_decryption:
                    print '* P'+str(i)+': Decryption Error!'
                else:
                    print '* P'+str(i)+': Error Decrypting Second Time!'
        print '---------------------------------------------------------'
        print
        print '\x1b[;32mNotes:\x1b[0m'
        print '\x1b[;32m1. Forward secrecy implies that no one can decrypt previous messages.\x1b[0m'
        print '   This is illustrated above by participants randomly trying to decrypt'
        print '   messages twice. Changing header and message keys are highlighted in the'
        print '   display above.'
        print '\x1b[;32m2. Future secrecy implies that current key compromise will not compromise\x1b[0m'
        print '   \x1b[;32mfuture keys.\x1b[0m'
        print '   This is accomplished above by the encrypting participant generating a'
        print '   new random ratchet key and passing it to other participants, where it'
        print '   is used in future key generation. The new ratchet key is highlighted'
        print '   in the display above.'
        print '\x1b[;32m3. Plausible deniability implies that conversation transcripts can be\x1b[0m'
        print '   \x1b[;32mconstructed with only public keys.\x1b[0m'
        print '   No participant secret keys are ever shared in this implementation.'
        sleep(5)
    except KeyboardInterrupt:
        saveState(p0, 0)
        saveState(p1, 1)
        saveState(p2, 2)
        saveState(p3, 3)
        saveState(p4, 4)
        saveState(p5, 5)
        saveState(p6, 6)
        saveState(p7, 7)
        print 'Whew! I\'m done...'
        exit()

