#!/usr/bin/env python

from smmp import Organizer, Participant, BummerUndecryptable, BadHMAC
from curve25519 import keys
from passlib.utils.pbkdf2 import pbkdf2
from random import randint
from time import sleep
from copy import deepcopy
import os
import binascii
import hashlib

def strxor(s0, s1):
    l = [chr(ord(a)^ord(b)) for a,b in zip(s0, s1)]
    return ''.join (l)

def hilite(text, c=False):
    attr = []
    if c:
        attr.append('41')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), text)

org = Organizer('my cool group name')

p0 = Participant('my cool group name')
p1 = Participant('my cool group name')
p2 = Participant('my cool group name')
p3 = Participant('my cool group name')
p4 = Participant('my cool group name')
p5 = Participant('my cool group name')
p6 = Participant('my cool group name')
p7 = Participant('my cool group name')

org.initState('my cool group name',
              {0: p0.identityPKey, 1: p1.identityPKey, 2: p2.identityPKey, 3: p3.identityPKey,
               4: p4.identityPKey, 5: p5.identityPKey, 6: p6.identityPKey, 7: p7.identityPKey},
              {0: p0.handshakePKey, 1: p1.handshakePKey, 2: p2.handshakePKey, 3: p3.handshakePKey,
               4: p4.handshakePKey, 5: p5.handshakePKey, 6: p6.handshakePKey, 7: p7.handshakePKey},
              {0: p0.ratchetPKey, 1: p1.ratchetPKey, 2: p2.ratchetPKey, 3: p3.ratchetPKey,
               4: p4.ratchetPKey, 5: p5.ratchetPKey, 6: p6.ratchetPKey, 7: p7.ratchetPKey},
              my_index=0)

p0.initState('my cool group name',
             org.state['pU'],
             org.state['pW'],
             deepcopy(org.state['R']),
             8,
             org.G[0],
             my_index=0)

p1.initState('my cool group name',
             org.state['pU'],
             org.state['pW'],
             deepcopy(org.state['R']),
             8,
             org.G[1],
             my_index=1)

p2.initState('my cool group name',
             org.state['pU'],
             org.state['pW'],
             deepcopy(org.state['R']),
             8,
             org.G[2],
             my_index=2)

p3.initState('my cool group name',
             org.state['pU'],
             org.state['pW'],
             deepcopy(org.state['R']),
             8,
             org.G[3],
             my_index=3)

p4.initState('my cool group name',
             org.state['pU'],
             org.state['pW'],
             deepcopy(org.state['R']),
             8,
             org.G[4],
             my_index=4)

p5.initState('my cool group name',
             org.state['pU'],
             org.state['pW'],
             deepcopy(org.state['R']),
             8,
             org.G[5],
             my_index=5)

p6.initState('my cool group name',
             org.state['pU'],
             org.state['pW'],
             deepcopy(org.state['R']),
             8,
             org.G[6],
             my_index=6)

p7.initState('my cool group name',
             org.state['pU'],
             org.state['pW'],
             deepcopy(org.state['R']),
             8,
             org.G[7],
             my_index=7)

participants = ('p0', 'p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7')
data_old = deepcopy(p0.state)
counter = 0
while True:
    counter += 1
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
                elif key == 'digest':
                    print 'dgt: '+hilite(binascii.b2a_base64(p0.state[key]).strip(), chg)
                else:
                    print '{:>3}'.format(key)+': '+hilite(binascii.b2a_base64(p0.state[key]).strip(), chg)
                chg = False
        print '--------------------------------------------------'

        data_old = deepcopy(p0.state)

        encrypter = randint(0,7)

        if counter % 5 == 0:
            exec('v, V = p' + str(encrypter) + '.genKey()')
            r = {}
            R = {}
            for i in range(len(participants)):
                key = keys.Private(secret=hashlib.sha256(str(i).zfill(32)).digest())
                r[i] = key.private
                R[i] = key.get_public().serialize()
            DHR = '\x00' * 32
            for i in range(len(participants)):
                DHR = strxor(DHR, R[i])
            exec('RK = hashlib.sha256(DHR + p' + str(encrypter) + '.genDH(v, DHR)).digest()')
            HK = pbkdf2(RK, b'\x01', 10, prf='hmac-sha256')
            NHK = pbkdf2(RK, b'\x02', 10, prf='hmac-sha256')
            MK = pbkdf2(RK, b'\x03', 10, prf='hmac-sha256')
            for i in range(len(participants)):
                exec('p' + str(i) + '.ratchetKey = r[i]')
                exec('p' + str(i) + '.state["v"] = deepcopy(v)')
                exec('p' + str(i) + '.state["R"] = deepcopy(R)')
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
            #try_twice = randint(0,9)
            try_twice = 1
            second_decryption = False
            try:
                print 'P'+str(i)+': '+eval(participants[i]+'.decrypt(ciphertexts[i][3:])') + ' and decrypted by P' + str(i)
                if try_twice == 0:
                    second_decryption = True
                    print ' ' + eval(participants[i]+'.decrypt(ciphertexts[i][3:])')
            #except (BummerUndecryptable, BadHMAC):
            except BadHMAC:
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
        print 'Whew! I\'m done...'
        exit()

