#!/usr/bin/env python3
"""
This is a reference implementation of LeMac and PetitMAC in python.

Written in 2024 by
  Augustin Bariant <augustin.bariant@ssi.gouv.fr>
  Gaëtan Leurent <gaetan.leurent@inria.fr>

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software to the
public domain worldwide. This software is distributed without any
warranty.

You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see
<http://creativecommons.org/publicdomain/zero/1.0/>.
"""

from lemac_petitmac import *

import ctypes
import random

# LeMac C interface
c_M128 = ctypes.c_char*16
c_LeCTX = ctypes.c_char*784
lemac_clib = ctypes.cdll.LoadLibrary("./lemac.so")
lemac_clib.lemac_init.argtypes = [ ctypes.POINTER(c_LeCTX), ctypes.POINTER(c_M128) ]
lemac_clib.lemac_init.restypes = ctypes.c_void_p
lemac_clib.lemac_MAC.argtypes = [ ctypes.POINTER(c_LeCTX), ctypes.POINTER(c_M128), ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.POINTER(c_M128) ]
lemac_clib.lemac_MAC.restypes = ctypes.c_void_p

# PetitMac C interface
c_PetitCTX = ctypes.c_char*688
petitmac_clib = ctypes.cdll.LoadLibrary("./petitmac.so")
petitmac_clib.petitmac_init.argtypes = [ ctypes.POINTER(c_PetitCTX), ctypes.POINTER(c_M128) ]
petitmac_clib.petitmac_init.restypes = ctypes.c_void_p
petitmac_clib.petitmac_MAC.argtypes = [ ctypes.POINTER(c_PetitCTX), ctypes.POINTER(c_M128), ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.POINTER(c_M128) ]
petitmac_clib.petitmac_MAC.restypes = ctypes.c_void_p


def lemac_c(key, nonce, message, verbose=False):
    M = ctypes.create_string_buffer(bytes(message))
    mac = c_M128(*[0 for _ in range(16)])
    ctx = ctypes.create_string_buffer(16*(9+2*11+18))
    lemac_clib.lemac_init(ctypes.pointer(ctx), ctypes.pointer(c_M128(*key)))
    lemac_clib.lemac_MAC(ctypes.pointer(ctx), ctypes.pointer(c_M128(*nonce)), M, len(message), ctypes.pointer(mac))
    return mac.raw
     
def petitmac_c(key, nonce, message, verbose=False):
    M = ctypes.create_string_buffer(bytes(message))
    mac = c_M128(*[0 for _ in range(16)])
    ctx = ctypes.create_string_buffer(16*(6+2*11+15))
    petitmac_clib.petitmac_init(ctypes.pointer(ctx), ctypes.pointer(c_M128(*key)))
    petitmac_clib.petitmac_MAC(ctypes.pointer(ctx), ctypes.pointer(c_M128(*nonce)), M, len(message), ctypes.pointer(mac))
    return mac.raw
     
    
def test(key, nonce, message, verbose=False):
    assert len(key) == 16
    assert len(nonce) == 16
    if verbose:
        print ("Key     : ", end="")
        printState(key)
        print ("Nonce   : ", end="")
        printState(nonce)
        print ("Message : ", end="")
        printState(message)
    macv0 = lemac(key,nonce,message,version=0)
    macv1 = lemac(key,nonce,message,version=1)
    mac_c = lemac_c(key,nonce,message)
    if (macv1 != mac_c):
        print("Error: incoherent results!")
        print ("LeMacv1 (python): ", end="")
        printState(macv1)
        print ("LeMacv1 (C)     : ", end="")
        printState(mac_c)
    assert(macv1 == mac_c)
    if verbose:
        print ("LeMacv0 : ", end="")
        printState(macv0)
        print ("LeMacv1 : ", end="")
        printState(macv1)
    mac   = petitmac(key,nonce,message)
    mac_c = petitmac_c(key,nonce,message)
    if (mac != mac_c):
        print("Error: incoherent results!")
        print ("PetitMac (python)  : ", end="")
        printState(mac)
        print ("PetitMac (C)       : ", end="")
        printState(mac_c)
    assert(mac == mac_c)
    if verbose:
        print ("PetitMac: ", end="")
        printState(mac)
        print()

test([0 for _ in range(16)], [0 for _ in range(16)], [], verbose=True)
test([0 for _ in range(16)], [0 for _ in range(16)], [0 for _ in range(16)], verbose=True)
test([i for i in range(16)], [i for i in range(16)], [i for i in range(65)], verbose=True)

print("Running test with random messages...")
for l in range(256):
    for _ in range(16):
        test(random.randbytes(16), random.randbytes(16), list(random.randbytes(l)))
print("Test passed")
