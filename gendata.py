#!/usr/bin/env python


import binascii
from curve25519 import keys

def genKey():
    key = keys.Private()
    privkey = key.private
    pubkey = key.get_public().serialize()
    return privkey, pubkey

if __name__ == '__main__':
    file_name = raw_input('Enter root filename to save output data: ')
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
    for i in range(num_users):
        with open(file_name + str(i) + '.dat', 'w') as f:
            f.write(binascii.b2a_base64(HK))
            f.write(binascii.b2a_base64(MK))
            f.write(binascii.b2a_base64(NHK))
            f.write(binascii.b2a_base64(RK))
            f.write(binascii.b2a_base64(v))
            f.write(group_name+'\n')
            f.write(str(i)+'\n')
            f.write(str(num_users)+'\n')
            for i in range(num_users):
                f.write(binascii.b2a_base64(R[i]))
