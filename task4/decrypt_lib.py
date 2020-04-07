#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
from tqdm import tqdm

check_pin = 395076

def crack_pin():
    raw = open('checkpin', 'rb').read()
    # Trying a 6-character all numeric pin
    for i in tqdm(range(100000, 999999)):
        h = SHA256.new()
        h.update(str(i))
        if h.digest() == raw:
            print( '[+] Hash cracked: ' + str(i) )
            break

if __name__=="__main__":
    crack_pin()
