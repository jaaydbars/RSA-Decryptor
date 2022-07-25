#!/usr/bin/python3

from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from zenipy import *
import sys
import time
from factordb.factordb import FactorDB
from itertools import compress
import re


#--------------------------Banner----------------------------------------

class style:
    HEADER    = '\033[95m'
    OBLUE    = '\033[94m'
    OGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC      = '\033[0m'

print(style.HEADER +   "       __                      __")
print(                 "      / ____ _____ ___  ______/ /")
print(                 " __  / / __ `/ __ `/ / / / __  / ")
print(                 "/ /_/ / /_/ / /_/ / /_/ / /_/ /  ")
print(                 "\____/\__,_/\__,_/\__, /\__,_/   ")
print(                 "                 /____/          ")
print(                 "      https://github.com/jaaydbars" + style.ENDC)
time.sleep(0.5)

#--------------------------Import File----------------------------------

print("Select your Public Key")
result = zenipy.file_selection(multiple=False, directory=False, save=False, confirm_overwrite=False, filename=False, title='Select your Public Key', width=90, height=90, timeout=None)

print(result)

#--------------------------Open file-------------------------------------

f = open(result, "r")

key = RSA.importKey(f.read())

e = key.e
n = key.n

log.info("n: %s" %n)
log.info("e: %s" %e)

#--------------------------Factorising-------------------------------------

def factorAPI():
    j = FactorDB(n)
    j.connect()
    print("Factorising...")
    j.get_factor_list()
    return j.get_factor_from_api()

def factorize(n):
    result = factorAPI()

    print("Prime Numbers are:") 

    b, c = compress(result, (1, 1)) #Assign Variables
    
    p = int(b[0])
    q = int(c[0])
    return p, q

p,q = factorize(n)
log.info("p: %s" %p)
log.info("q: %s" %q)

#---------------------Modular multiplicative inverse function------------------

m = n-(p+q-1)


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

d = modinv(e, m)

#--------------------------------------------------------------------------------

log.info("m: %s" %m)
log.info("d: %s" %d)

key = RSA.construct((n, e, d, p, q))
print("\n" + key.exportKey().decode() + "\n")
