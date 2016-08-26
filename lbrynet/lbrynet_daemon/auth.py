import os
from hashlib import sha256
import time
import struct
import binascii


def sha(x):
    return bytearray(sha256(x).digest())


def generate_secret():
    seed = os.urandom(1024)
    return binascii.hexlify(sha(seed))


def initialize_n():
    return int(os.urandom(2).encode('hex'), 16)


def get_token(secret, n, id):
    decoded_secret = binascii.unhexlify(secret)
    htime = sha(struct.pack("!I", int(time.time())))
    decoded_id = binascii.unhexlify(id)
    combined = bytearray(i ^ (n % 256) for i in htime)
    token = sha(decoded_secret + combined + decoded_id)
    return binascii.hexlify(token)


def validate_token(secret, n, token, id):
    t = get_token(secret, n, id)
    if t == token:
        return True
    return False