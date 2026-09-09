#!/usr/bin/python
"""Independent SRP server equations; emits deterministic offline C fixtures.

Only synthetic credentials. Compatible with OS X's Python 2.7 and Python 3.
"""
from __future__ import print_function
import hashlib
import hmac
import binascii
import struct

N = int('AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73', 16)
g = 2
a = int('dd' * 32, 16)
b = int('ab' * 32, 16)
user = b'test@example.invalid'
password = b'synthetic:password'

def raw(n):
    s = '%x' % n
    return binascii.unhexlify(('0' if len(s) % 2 else '') + s)

def pad(n):
    return raw(n).rjust(256, b'\0')

def H(*parts):
    return hashlib.sha256(b''.join(parts)).digest()

def number(d):
    return int(binascii.hexlify(d), 16)

def pbkdf(password, salt, rounds):
    u = hmac.new(password, salt + struct.pack('>I', 1), hashlib.sha256).digest()
    acc = number(u)
    for _ in range(rounds - 1):
        u = hmac.new(password, u, hashlib.sha256).digest()
        acc ^= number(u)
    return raw(acc).rjust(32, b'\0')

def array(name, value):
    print('static const unsigned char %s[] = {%s};' % (name, ','.join('0x%02x' % x for x in bytearray(value))))

for index, (protocol, salt, client_private, server_private) in enumerate([
        ('s2k', b'ordinarysalt1234', a, b), ('s2k_fo', b'ordinarysalt1234', a, b),
        ('s2k', b'\0\0leadingzeros!!', a, b),
        ('s2k', b'ordinarysalt1234', 1, b),
        # Deliberately constructed B = k*v + 1 makes S = 1, testing K padding.
        ('s2k', b'ordinarysalt1234', a, 0)]):
    pw = H(password)
    if protocol == 's2k_fo':
        pw = binascii.hexlify(pw)
    x = number(H(salt, H(b':', pbkdf(pw, salt, 5))))
    v = pow(g, x, N)
    k = number(H(pad(N), pad(g)))
    A = pow(g, client_private, N)
    B = (k*v + pow(g, server_private, N)) % N
    u = number(H(pad(A), pad(B)))
    # Server side, independent of the client's (B - k*g^x)^(a + u*x).
    K = H(pad(pow((A * pow(v, u, N)) % N, server_private, N)))
    xor = raw(number(H(pad(N))) ^ number(H(pad(g)))).rjust(32, b'\0')
    M1 = H(xor, H(user), salt, pad(A), pad(B), K)
    M2 = H(pad(A), M1, K)
    for name, data in [('salt', salt), ('B', pad(B)), ('M1', M1), ('M2', M2), ('K', K)]:
        array('%s%d' % (name, index), data)
