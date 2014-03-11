#!/usr/bin/env python

from binascii import hexlify, b2a_base64
import hashlib

# If a secure random number generator is unavailable, exit with an error.
try:
    import Crypto.Random.random
    secure_random = Crypto.Random.random.getrandbits
except ImportError:
    import OpenSSL
    secure_random = lambda x: long(hexlify(OpenSSL.rand.bytes(x>>3)), 16)

class BD(object):

    def __init__(self, group_size, my_index):
        # 2048 bit MODP prime from RFC 3526
        self.group_size = group_size
        self.my_index = my_index
        self.g = 2
        self.prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.privKey = secure_random(2040)
        self.pubKey = pow(self.g, self.privKey, self.prime)

    def inverse(self, a, b, p):
        """
        Solves a congruence of the form a x = b mod p
        where p is prime, returns x
        """
        x = 0
        newx = 1
        r = p
        newr = a
        while newr != 0:
            quotient = r / newr
            prov = x
            x = newx
            newx = prov - quotient * newx
            prov = r
            r = newr
            newr = prov - quotient * newr
        if r > 1:
            return 'a is not invertable'
        return (b * x) % p


    def round1(self, pubkeys={}):
        self.k = pubkeys # pub keys for group members
        self.my_x = self.inverse(pow(self.k[(self.my_index - 1) % self.group_size],
                                self.privKey, self.prime),
                                pow(self.k[(self.my_index + 1) % self.group_size],
                                self.privKey, self.prime), self.prime)

    def round2(self, round2keys={}):
        self.x = round2keys # round 2 keys for group members
        self.K = pow(self.k[(self.my_index - 1) % self.group_size],
                            (self.group_size * self.privKey), self.prime)
        for i in range(self.group_size-1):
            self.K = self.K * pow(self.x[(self.my_index + i) % self.group_size],
                                 (self.group_size - i - 1))
        self.integer_secret = pow(self.K, 1, self.prime)
        return b2a_base64(hashlib.sha256(str(self.integer_secret)).digest()).strip()

if __name__ == '__main__':

    a = BD(3, 0)
    b = BD(3, 1)
    c = BD(3, 2)

    a.round1(pubkeys = {0: a.pubKey, 1:b.pubKey, 2:c.pubKey})
    b.round1(pubkeys = {0: a.pubKey, 1:b.pubKey, 2:c.pubKey})
    c.round1(pubkeys = {0: a.pubKey, 1:b.pubKey, 2:c.pubKey})

    a_secret = a.round2(round2keys = {0: a.my_x, 1:b.my_x, 2:c.my_x})
    b_secret = b.round2(round2keys = {0: a.my_x, 1:b.my_x, 2:c.my_x})
    c_secret = c.round2(round2keys = {0: a.my_x, 1:b.my_x, 2:c.my_x})

    assert a_secret == b_secret, 'Secrets don\'t match!'
    assert b_secret == c_secret, 'Secrets don\'t match!'

    print 'Secret is: ', a_secret
