import hashlib
import hmac
import binascii
import hmac
import gnupg
import os
import sys
from time import time, sleep
from passlib.utils.pbkdf2 import pbkdf2
from curve25519 import keys

user_path = os.path.expanduser('~')
KEYRING = [user_path+'/.gnupg/pubring.gpg']
SECRET_KEYRING = [user_path+'/.gnupg/secring.gpg']
GPGBINARY = 'gpg'

gpg = gnupg.GPG(gnupghome=user_path+'/.axolotl', gpgbinary=GPGBINARY, keyring=KEYRING,
                secret_keyring=SECRET_KEYRING, options=['--throw-keyids',
                '--personal-digest-preferences=sha256','--s2k-digest-algo=sha256'])
gpg.encoding = 'latin-1'

class Organizer:

    def __init__(self, group_name):
        self.group_name = group_name
        self.org_num = 0
        self.mode = True
        self.state = {}
        self.state['u'], self.state['pU'] = self.genKey()
        self.state['w'], self.state['pW'] = self.genKey()

    def strxor(self, s0, s1):
        l = [chr(ord(a)^ord(b)) for a,b in zip(s0, s1)]
        return ''.join (l)

    def tripleDH(self, u, w, K, B):
        return hashlib.sha256(self.genDH(u, K) + self.genDH(w, B) + self.genDH(w, K)).digest()

    def genDH(self, a, B):
        key = keys.Private(secret=a)
        return key.get_shared_key(keys.Public(B))

    def genKey(self):
        key = keys.Private()
        privkey = key.private
        pubkey = key.get_public().serialize()
        return privkey, pubkey

    def initState(self, group_name, identityKeys, handshakeKeys, ratchetKeys, my_index=2):
        """
        Here group_name is the group name, identityKeys, handshakeKeys, and ratchetKeys
        are dictionaries with key:value pairs equal to the participant index number
        and the Key value.
        """

        self.group_size = len(identityKeys)

        self.L = {}
        for i in range(self.group_size):
            self.L[i] = self.tripleDH(self.state['u'], self.state['w'],
                                      identityKeys[i],
                                      handshakeKeys[i])
        mkey = '\x00' * 32
        for i in range(self.group_size):
            mkey = self.strxor(mkey, self.L[i])
        mkey = hashlib.sha256(mkey).digest()
        self.G = {}
        for i in range(self.group_size):
            self.G[i] = self.genDH(self.state['w'], ratchetKeys[i])# initialize G strings ;-)
        for i in range(self.group_size):
            for j in range(self.group_size):
                if i != j:
                    self.G[j] = self.strxor(self.G[j], self.L[i])

        self.state = \
               { 'group_name': self.group_name,
                 'my_index': my_index,
                 'pU': self.state['pU'],
                 'pW': self.state['pW'],
                 'R' : ratchetKeys,
               }

#######################################################################################

class Participant:

    def __init__(self, group_name):
        self.group_name = group_name
        self.mode = False
        self.state = {}
        self.identityKey, self.identityPKey = self.genKey()
        self.handshakeKey, self.handshakePKey = self.genKey()
        self.ratchetKey, self.ratchetPKey = self.genKey()
        self.resync_required = False

    def strxor(self, s0, s1):
        l = [chr(ord(a)^ord(b)) for a,b in zip(s0, s1)]
        return ''.join (l)

    def tripleDH(self, k, b, U, W):
        return hashlib.sha256(self.genDH(k, U) + self.genDH(b, W) + self.genDH(k, W)).digest()

    def genDH(self, a, B):
        key = keys.Private(secret=a)
        return key.get_shared_key(keys.Public(B))

    def genKey(self):
        key = keys.Private()
        privkey = key.private
        pubkey = key.get_public().serialize()
        return privkey, pubkey

    def initState(self, group_name, group_identityPKey, group_handshakePKey, group_ratchetKeys, group_size, G, my_index=1):
        """
        Here group_name is the group name, identityKeys, handshakeKeys, and ratchetKeys
        are dictionaries with key:value pairs equal to the participant index number
        and the Key value.
        """

        self.group_size = len(group_ratchetKeys)
        mkey = hashlib.sha256(self.strxor(self.tripleDH(self.identityKey, self.handshakeKey,
                              group_identityPKey, group_handshakePKey),
                              self.strxor(G, self.genDH(self.ratchetKey,
                              group_handshakePKey)))).digest()
        RK = pbkdf2(mkey, b'\x00', 10, prf='hmac-sha256')
        HK = pbkdf2(mkey, b'\x01', 10, prf='hmac-sha256')
        NHK = pbkdf2(mkey, b'\x02', 10, prf='hmac-sha256')
        MK = pbkdf2(mkey, b'\x03', 10, prf='hmac-sha256')
        v = pbkdf2(mkey, b'\x04', 10, prf='hmac-sha256')
        DHR = None

        self.state = \
               { 'group_name': self.group_name,
                 'my_index': my_index,
                 'RK': RK,
                 'HK': HK,
                 'NHK': NHK,
                 'MK': MK,
                 'R' : group_ratchetKeys,
                 'v' : v,
               }

    def encrypt(self, plaintext):
        rnew, Rnew = self.genKey()
        msg1 = self.enc(self.state['HK'], str(self.state['my_index']).zfill(3) + Rnew)
        msg2 = self.enc(self.state['MK'], plaintext)
        pad_length = 103 - len(msg1)
        pad = os.urandom(pad_length - 1) + chr(pad_length)
        msg = msg1 + pad + msg2
        mac = hmac.new(self.state['v'], msg, hashlib.sha256).digest()
        self.state['R'][self.state['my_index']] = Rnew
        DHR = '\x00' * 32
        for i in range(self.group_size):
            DHR = self.strxor(DHR, self.genDH(self.state['v'], self.state['R'][i]))
        DHR = hashlib.sha256(DHR).digest()
        self.state['RK'] = hashlib.sha256(self.state['RK'] +
                   self.genDH(self.state['v'], DHR)).digest()
        self.state['HK'] = self.state['NHK']
        self.state['NHK'] = pbkdf2(self.state['RK'], b'\x02', 10, prf='hmac-sha256')
        self.state['MK'] = pbkdf2(self.state['RK'], b'\x03', 10, prf='hmac-sha256')
        return msg + mac

    def enc(self, key, plaintext):
        key = binascii.hexlify(key)
        msg = gpg.encrypt(plaintext, recipients=None, symmetric='AES256', armor=False,
                                always_trust=True, passphrase=key)
        return msg.data[6:]

    def dec(self, key, encrypted):
        key = binascii.hexlify(key)
        msg = gpg.decrypt(binascii.unhexlify('8c0d04090308') + encrypted,
                          passphrase=key, always_trust=True)
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
        self.state['R'][Pnum] = header[3:]
        body = self.dec(self.state['MK'], msg[103:-32])
        if not body or body == '':
            raise BummerUndecryptable
        DHR = '\x00' * 32
        for i in range(self.group_size):
            DHR = self.strxor(DHR, self.genDH(self.state['v'], self.state['R'][i]))
        DHR = hashlib.sha256(DHR).digest()
        self.state['RK'] = hashlib.sha256(self.state['RK'] +
                   self.genDH(self.state['v'], DHR)).digest()
        self.state['HK'] = self.state['NHK']
        self.state['NHK'] = pbkdf2(self.state['RK'], b'\x02', 10, prf='hmac-sha256')
        self.state['MK'] = pbkdf2(self.state['RK'], b'\x03', 10, prf='hmac-sha256')
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
        count = 0
        while count < self.state['my_index'] + 1:
            sleep(0.5)
            if not self.resync_required:
                break
            count += 1
        v, V = self.genKey()
        msg1 = self.enc(self.state['v'], '\x00' + v)
        mac = hmac.new(self.state['v'], msg1, hashlib.sha256).digest()
        R = {}
        for i in range(len(self.state['R'])):
            R[i] = hashlib.sha256(v + str(i)).digest()
        DHR = '\x00' * 32
        for i in range(len(self.state['R'])):
            DHR = self.strxor(DHR, R[i])
        RK = hashlib.sha256(DHR + self.genDH(v, DHR)).digest()
        HK = pbkdf2(RK, b'\x01', 10, prf='hmac-sha256')
        NHK = pbkdf2(RK, b'\x02', 10, prf='hmac-sha256')
        MK = pbkdf2(RK, b'\x03', 10, prf='hmac-sha256')
        if self.resync_required:
            self.resync_required = False
            self.state['v'] = v
            self.state['RK'] = RK
            self.state['HK'] = HK
            self.state['NHK'] = NHK
            self.state['MK'] = MK
            self.state['R'] = R
            sock.send(msg1 + mac + 'EOP')
            return 'Resync sent'
        return 'Resync send message aborted'

    def resyncReceive(self, ciphertext):
        self.resync_required = False
        try:
            plaintext = self.dec(self.state['v'], ciphertext)
        except (DecodeError, ValueError, UnicodeDecodeError):
            raise BummerUndecryptable
        if plaintext[:1] != '\x00' or len(plaintext[1:]) != 32 or ciphertext is None:
            raise BummerUndecryptable
        else:
            self.state['v'] = plaintext[1:]
            for i in range(len(self.state['R'])):
                self.state['R'][i] = hashlib.sha256(self.state['v'] + str(i)).digest()
            DHR = '\x00' * 32
            for i in range(len(self.state['R'])):
                DHR = self.strxor(DHR, self.state['R'][i])
            self.state['RK'] = hashlib.sha256(DHR +
                       self.genDH(self.state['v'], DHR)).digest()
            self.state['HK'] = pbkdf2(self.state['RK'], b'\x01', 10, prf='hmac-sha256')
            self.state['NHK'] = pbkdf2(self.state['RK'], b'\x02', 10, prf='hmac-sha256')
            self.state['MK'] = pbkdf2(self.state['RK'], b'\x03', 10, prf='hmac-sha256')
            return 'Ratchet resync message received - System resynced!\n'

class BummerUndecryptable(Exception):
    def __init__(self):
        pass

class BadHMAC(Exception):
    def __init__(self):
        pass
