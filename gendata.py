#!/usr/bin/env python


import binascii
import gnupg
from curve25519 import keys
from contextlib import contextmanager
from getpass import getpass
from StringIO import StringIO

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

def genKey():
    key = keys.Private()
    privkey = key.private
    pubkey = key.get_public().serialize()
    return privkey, pubkey

def getPass(message):
    passphrase=''
    passphrase1='1'
    while passphrase != passphrase1:
        passphrase = getpass(message)
        passphrase1 = getpass('Repeat: ')
        if passphrase != passphrase1:
            print 'Passphrases did not match'
    return passphrase

if __name__ == '__main__':
    file_name = raw_input('Enter filename to save output data: ')
    passphrase = getPass('What is the passphrase for the file: ')
    num_users = int(raw_input('Enter the number of users in the group: '))
    group_name = raw_input('Enter the group name: ')
    MK, MKP = genKey()
    HK, HKP = genKey()
    NHK, NHKP = genKey()
    RK, RKP = genKey()
    v, V = genKey()
    R = {}
    for i in range(num_users):
        R[i], r = genKey()
    with encFile(file_name, passphrase) as f:
        f.write(binascii.b2a_base64(HK))
        f.write(binascii.b2a_base64(MK))
        f.write(binascii.b2a_base64(NHK))
        f.write(binascii.b2a_base64(RK))
        f.write(binascii.b2a_base64(v))
        f.write(group_name+'\n')
        f.write('0'+'\n')
        for i in range(num_users):
            f.write(binascii.b2a_base64(R[i]))
