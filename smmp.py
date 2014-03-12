import hashlib
import hmac
import binascii
import hmac
import gnupg
import os
import sys
from copy import deepcopy
from time import time, sleep
from passlib.utils.pbkdf2 import pbkdf2
from curve25519 import keys
from bd import BD

user_path = os.path.expanduser('~')
KEYRING = [user_path+'/.gnupg/pubring.gpg']
SECRET_KEYRING = [user_path+'/.gnupg/secring.gpg']
GPGBINARY = 'gpg'

gpg = gnupg.GPG(gnupghome=user_path+'/.axolotl', gpgbinary=GPGBINARY, keyring=KEYRING,
                secret_keyring=SECRET_KEYRING, options=['--throw-keyids',
                '--personal-digest-preferences=sha256','--s2k-digest-algo=sha256'])
gpg.encoding = 'latin-1'

class Participant:

    def __init__(self, group_name, group_size, my_index):
        self.group_name = group_name
        self.group_size = group_size
        self.my_index = my_index
        self.mode = False
        self.state = {}
        self.identityKey, self.identityPKey = self.genKey()
        self.ratchetKey, self.ratchetPKey = self.genKey()
        self.resync_required = False
        self.bd = BD(self.group_size, self.my_index)

    def strxor(self, s0, s1):
        l = [chr(ord(a)^ord(b)) for a,b in zip(s0, s1)]
        return ''.join (l)

    def s2l(self, s):
        """
        string to long
        """
        return long(binascii.hexlify(s), 16)

    def l2s(self, n):
        """
        long to string
        """
        num = '%x' % n
        if len(num) % 2:
            num = '0' + num
        return binascii.unhexlify(num)


    def tripleDH(self, b, r, B, R):
        return hashlib.sha256(self.genDH(r, B) + self.genDH(b, R) + self.genDH(r, R)).digest()

    def genDH(self, a, B):
        key = keys.Private(secret=a)
        return key.get_shared_key(keys.Public(B))

    def genKey(self):
        key = keys.Private()
        privkey = key.private
        pubkey = key.get_public().serialize()
        return privkey, pubkey

    def initBD(self, identityKeys, handshakeKeys, ratchetKeys):
        for i in range(self.group_size):
            if i != self.my_index:
                sent_mac = binascii.a2b_base64(handshakeKeys[i])[-32:]
                handshakeKeys[i] = self.s2l(binascii.a2b_base64(handshakeKeys[i])[:-32])
                mac = hmac.new(self.tripleDH(self.identityKey, self.ratchetKey,
                               identityKeys[i], ratchetKeys[i]),
                               str(handshakeKeys[i]), hashlib.sha256).digest()
                assert mac == sent_mac, 'Bad signature - identity does not match for participant '+str(i)
        self.bd.round1(pubkeys = handshakeKeys)
        x = {}
        x[self.my_index] = self.bd.my_x
        print 'Your round 2 key is '+binascii.b2a_base64(self.l2s(self.bd.my_x))
        for i in range(self.group_size):
            if i != self.my_index:
                x[i] = self.s2l(binascii.a2b_base64(raw_input('Input user '+str(i)+'\'s round 2 key: ')))
        return self.bd.round2(round2keys=x)

    def initState(self, group_name, identityKeys, handshakeKeys,
                  ratchetKeys):
        """
        Here group_name is the group name, identityKeys, handshakeKeys, and ratchetKeys
        are dictionaries with key:value pairs equal to the participant index number
        and the Key value.
        """
        mkey = self.initBD(identityKeys, handshakeKeys, ratchetKeys)
        del self.bd

        RK = pbkdf2(mkey, b'\x00', 10, prf='hmac-sha256')
        HK = pbkdf2(mkey, b'\x01', 10, prf='hmac-sha256')
        MK = pbkdf2(mkey, b'\x02', 10, prf='hmac-sha256')
        v = pbkdf2(mkey, b'\x03', 10, prf='hmac-sha256')

        self.state = \
               { 'group_name': self.group_name,
                 'my_index': self.my_index,
                 'RK': RK,
                 'HK': HK,
                 'MK': MK,
                 'initpubR' : deepcopy(ratchetKeys),
                 'initr' : deepcopy(self.ratchetKey),
                 'R' : ratchetKeys,
                 'v' : v,
                 'digest' : '\x00' * 32
               }

    def encrypt(self, plaintext):
        rnew, Rnew = self.genKey()
        messages = {}
        self.state['digest'] = self.strxor(self.state['digest'], hashlib.sha256(plaintext).digest())
        for i in range(self.group_size):
            if i != self.state['my_index']:
                otp = self.strxor(hashlib.sha256(self.genDH(self.ratchetKey, self.state['R'][i])).digest(), self.state['digest'])
                encrypted_Rnew = self.strxor(Rnew, otp)
                msg1 = self.enc(self.state['HK'], str(self.state['my_index']).zfill(3) + encrypted_Rnew)
                msg2 = self.enc(self.state['MK'], plaintext)
                pad_length = 103 - len(msg1)
                pad = os.urandom(pad_length - 1) + chr(pad_length)
                msg = msg1 + pad + msg2
                mac = hmac.new(self.state['v'], msg, hashlib.sha256).digest()
                # not part of protocol
                messages[i] = str(i).zfill(3) + msg + mac
        self.ratchetKey = rnew
        self.state['R'][self.state['my_index']] = Rnew
        DHR = ''
        for i in range(self.group_size):
            DHR = DHR + self.genDH(self.state['v'], self.state['R'][i])
        DHR = hashlib.sha256(DHR).digest()
        self.state['RK'] = hashlib.sha256(self.state['RK'] +
                   self.genDH(self.state['v'], DHR)).digest()
        self.state['HK'] = pbkdf2(self.state['RK'], b'\x01', 10, prf='hmac-sha256')
        self.state['MK'] = pbkdf2(self.state['RK'], b'\x02', 10, prf='hmac-sha256')
        return messages

    def enc(self, key, plaintext):
        key = binascii.hexlify(key)
        msg = gpg.encrypt(plaintext, recipients=None, symmetric='AES256', armor=False,
                                always_trust=True, passphrase=key)
        return msg.data[6:]

    def dec(self, key, encrypted):
        key = binascii.hexlify(key)
        try:
            msg = gpg.decrypt(binascii.unhexlify('8c0d04090308') + encrypted,
                              passphrase=key, always_trust=True)
        except ValueError:
            raise BummerUndecryptable
        return msg.data

    def decrypt(self, msg):
        if hmac.new(self.state['v'], msg[:-32], hashlib.sha256).digest() != msg[-32:]:
            raise BadHMAC
        pad = msg[102:103]
        pad_length = ord(pad)
        msg1 = msg[:103-pad_length]

        header = self.dec(self.state['HK'], msg1)
        if not header or header == '':
            return self.resyncReceive(msg[:-32])
        Pnum = int(header[:3])

        body = self.dec(self.state['MK'], msg[103:-32])
        if not body or body == '':
            raise BummerUndecryptable
        self.state['digest'] = self.strxor(hashlib.sha256(body).digest(), self.state['digest'])
        otp = self.strxor(hashlib.sha256(self.genDH(self.ratchetKey, self.state['R'][Pnum])).digest(), self.state['digest'])
        self.state['R'][Pnum] = self.strxor(header[3:35], otp)
        DHR = ''
        for i in range(self.group_size):
            DHR = DHR + self.genDH(self.state['v'], self.state['R'][i])
        DHR = hashlib.sha256(DHR).digest()
        self.state['RK'] = hashlib.sha256(self.state['RK'] +
                   self.genDH(self.state['v'], DHR)).digest()
        self.state['HK'] = pbkdf2(self.state['RK'], b'\x01', 10, prf='hmac-sha256')
        self.state['MK'] = pbkdf2(self.state['RK'], b'\x02', 10, prf='hmac-sha256')
        return body

    def printState(self):
        for key in sorted(self.state):
             if 'priv' in key:
                 pass
             else:
                 if self.state[key] is None:
                     print key + ': None'
                 elif type(self.state[key]) is bool:
                     if self.state[key]:
                         print key + ': True'
                     else:
                         print key + ': False'
                 elif type(self.state[key]) is str:
                     try:
                         self.state[key].decode('ascii')
                         print key + ': ' + self.state[key]
                     except UnicodeDecodeError:
                         print key + ': ' + binascii.b2a_base64(self.state[key]).strip()
                 elif key == 'R':
                     for index, item in self.state[key].iteritems():
                         print ' R'+str(index)+': '+binascii.b2a_base64(item).strip()
                 else:
                     print key + ': ' + str(self.state[key])

    def resyncSend(self, sock):
        SLOTTIME = 1 # TDMA timeslot width for resync packets (integer seconds)
        grp = SLOTTIME * self.group_size
        my = SLOTTIME * self.state['my_index']
        while int(time()) % grp != my:
            sleep(0.01 * SLOTTIME)
            if not self.resync_required:
                return 'Resync send message aborted'
        vnew, pVnew = self.genKey()
        rnew, pRnew = self.genKey()
        msg1 = self.enc(self.state['v'], '\x00' + str(self.state['my_index']).zfill(3) + vnew + pRnew)
        mac = hmac.new(self.state['v'], msg1, hashlib.sha256).digest()
        v = hashlib.sha256(self.state['v'] + vnew).digest()
        self.state['initr'] = rnew
        self.state['initpubR'][self.state['my_index']] = pRnew
        DHR = ''
        for i in range(len(self.state['R'])):
            DHR = DHR + self.state['initpubR'][i]
        DHR = hashlib.sha256(DHR).digest()
        RK = hashlib.sha256(v + self.genDH(v, DHR)).digest()
        HK = pbkdf2(RK, b'\x01', 10, prf='hmac-sha256')
        MK = pbkdf2(RK, b'\x02', 10, prf='hmac-sha256')
        if self.resync_required:
            self.resync_required = False
            self.ratchetKey = deepcopy(self.state['initr'])
            self.state['R'] = deepcopy(self.state['initpubR'])
            self.state['v'] = v
            self.state['RK'] = RK
            self.state['HK'] = HK
            self.state['MK'] = MK
            self.state['digest'] = '\x00' * 32
            sock.send('999' + msg1 + mac + 'EOP')
            return 'Resync sent'
        return 'Resync send message aborted'

    def resyncReceive(self, ciphertext):
        try:
            plaintext = self.dec(self.state['v'], ciphertext)
        except (DecodeError, ValueError):
            raise BummerUndecryptable
        if plaintext[:1] != '\x00' or len(plaintext) != 68 or ciphertext is None:
            raise BummerUndecryptable
        else:
            self.resync_required = False
            self.state['v'] = hashlib.sha256(self.state['v'] + plaintext[4:36]).digest()
            self.state['initpubR'][int(plaintext[1:4])] = plaintext[36:68]
            self.ratchetKey = deepcopy(self.state['initr'])
            self.state['R'] = deepcopy(self.state['initpubR'])
            DHR = ''
            for i in range(len(self.state['R'])):
                DHR = DHR + self.state['R'][i]
            DHR = hashlib.sha256(DHR).digest()
            self.state['RK'] = hashlib.sha256(self.state['v'] +
                       self.genDH(self.state['v'], DHR)).digest()
            self.state['HK'] = pbkdf2(self.state['RK'], b'\x01', 10, prf='hmac-sha256')
            self.state['MK'] = pbkdf2(self.state['RK'], b'\x02', 10, prf='hmac-sha256')
            self.state['digest'] = '\x00' * 32
            return 'Ratchet resync message received - System resynced!\n'

class BummerUndecryptable(Exception):
    def __init__(self):
        pass

class BadHMAC(Exception):
    def __init__(self):
        pass

class BadDIGEST(Exception):
    def __init__(self):
        pass
