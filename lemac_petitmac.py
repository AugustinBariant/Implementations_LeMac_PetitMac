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



from math import ceil

# Use AES python implementation from https://github.com/boppreh/aes/blob/master/aes.py
from aes import AES, shift_rows, sub_bytes, mix_columns, xor_bytes, bytes2matrix, matrix2bytes, add_round_key

def printState(s):
    string = ""
    for i in range(len(s)):
        string += "{:02x}".format(s[i])
    print(string)

def AES_round_no_key(plaintext):
    """
    One round of AES without the addkey.
    """
    assert len(plaintext) == 16

    plain_state = bytes2matrix(plaintext)
    sub_bytes(plain_state)
    shift_rows(plain_state)
    mix_columns(plain_state)
    return matrix2bytes(plain_state)

def AES_modified(plaintext, subkeys):
    """
    Encrypts a single block of 16 byte long plaintext.
    """
    assert len(plaintext) == 16

    key_matrices = [bytes2matrix(k) for k in subkeys]
    plain_state = bytes2matrix(plaintext)

    add_round_key(plain_state, key_matrices[0])

    for i in range(10):
        sub_bytes(plain_state)
        shift_rows(plain_state)
        mix_columns(plain_state)
        if i != 9:
            add_round_key(plain_state, key_matrices[i+1])


    return matrix2bytes(plain_state)

def get_constant(i):
    constant_bytes = [0  for _ in range(16)]
    constant_bytes[0] = i
    return constant_bytes

def lemac_UHF(state, message, verbose=False, version=1):
    assert len(message) % (4*16) == 0, "Message size not a multiple of 4*128 bits"
    assert(version==0 or version==1)
    if version == 1:
        message += [0 for _ in range(4*4*16)]
        RR = [0 for _ in range(16)]
    else:
        message += [0 for _ in range(3*4*16)]

    R0 = [0 for _ in range(16)]
    R1 = [0 for _ in range(16)]
    R2 = [0 for _ in range(16)]
    new_state = [[0 for _ in range(16)] for _ in range(9)]
    if verbose:
        printState(state[0])
    for i in range(len(message)//(64)):
        new_state[0] = xor_bytes(state[0],state[8])
        for j in range(1,9):
            new_state[j] = AES_round_no_key(state[j-1])
        state[8] = xor_bytes(new_state[8],message[(4*i+3)*16:(4*i+4)*16])
        state[7] = xor_bytes(new_state[7],message[(4*i+1)*16:(4*i+2)*16])
        state[6] = xor_bytes(new_state[6],message[(4*i+1)*16:(4*i+2)*16])
        state[5] = xor_bytes(new_state[5],message[(4*i+0)*16:(4*i+1)*16])
        state[4] = xor_bytes(new_state[4],message[(4*i+0)*16:(4*i+1)*16])
        state[3] = xor_bytes(new_state[3],R1)
        state[3] = xor_bytes(state[3],R2)
        state[2] = xor_bytes(new_state[2],message[(4*i+3)*16:(4*i+4)*16])
        state[1] = xor_bytes(new_state[1],message[(4*i+3)*16:(4*i+4)*16])
        state[0] = xor_bytes(new_state[0],message[(4*i+2)*16:(4*i+3)*16])
        if version == 1:
            R2 = R1
            R1 = R0
            R0 = xor_bytes(RR,message[(4*i+1)*16:(4*i+2)*16])
            RR = message[(4*i+2)*16:(4*i+3)*16] 
        else:
            R2 = R1
            R1 = xor_bytes(R0,message[(4*i+1)*16:(4*i+2)*16])
            R0 = message[(4*i+2)*16:(4*i+3)*16] 
        if verbose:
            printState(state[0])
    return state
        
        

def lemac(key, nonce, message, verbose=False, version=1):
    # Copy message because we modify it
    message = message[:]
    # Padding
    message += ([1] + [0 for _ in range(len(message) + 1, 64*ceil((len(message) + 1)/64))])
    init_state = [AES(key).encrypt_block(get_constant(i)) for i in range(9)]
    final_keys = [AES(key).encrypt_block(get_constant(i)) for i in range(9,27)]
    nonce_key_1 = AES(key).encrypt_block(get_constant(27))
    nonce_key_2 = AES(key).encrypt_block(get_constant(28))
    

    state = lemac_UHF(init_state, message, verbose, version)

    if verbose:
        printState(state[0])
    T = xor_bytes(nonce, AES(nonce_key_1).encrypt_block(nonce))
    for i in range(9):
        T = xor_bytes(T,AES_modified(state[i],final_keys[i:i+10]))
    return AES(nonce_key_2).encrypt_block(T)
    

def petitmac_UHF(state, message, verbose=False):
    assert len(message) % (16) == 0, "Message size not a multiple of 128 bits"
    R0 = [0 for _ in range(16)]
    R1 = [0 for _ in range(16)]
    R2 = [0 for _ in range(16)]
    R3 = [0 for _ in range(16)]
    R4 = [0 for _ in range(16)]
    t = [0 for _ in range(16)]
    new_R = [[0 for _ in range(16)] for _ in range(5)]
    if verbose:
        printState(state[0])
    for i in range(len(message)//(16)):
        t = xor_bytes(AES_round_no_key(state[0]),message[i*16:(i+1)*16])
        t = xor_bytes(t,R4)
        new_R[0] = xor_bytes(message[i*16:(i+1)*16],R3)
        new_R[1] = xor_bytes(R4,new_R[0])
        new_R[2] = xor_bytes(R4,R0)
        new_R[3] = R1
        new_R[4] = R2
        state[0] = xor_bytes(AES_round_no_key(t),new_R[0])
        R0 = new_R[0]
        R1 = new_R[1]
        R2 = new_R[2]
        R3 = new_R[3]
        R4 = new_R[4]
        if verbose:
            printState(state[0])
    return state,R0,R1,R2,R3,R4
        

        

def petitmac(key, nonce, message, verbose=False):
    # Copy message because we modify it
    message = message[:]
    # Padding
    message += ([1] + [0 for _ in range(len(message) + 1, 16*ceil((len(message) + 1)/16))])
    init_state = [AES(key).encrypt_block(get_constant(i)) for i in range(1)]
    final_keys = [AES(key).encrypt_block(get_constant(i)) for i in range(1,16)]
    nonce_key_1 = AES(key).encrypt_block(get_constant(16))
    nonce_key_2 = AES(key).encrypt_block(get_constant(17))
    

    state,R0,R1,R2,R3,R4 = petitmac_UHF(init_state,message,verbose)

    if verbose:
        printState(state[0])
    T = xor_bytes(nonce, AES(nonce_key_1).encrypt_block(nonce))
    
    T = xor_bytes(T,AES_modified(state[0],final_keys[:10]))
    T = xor_bytes(T,AES_modified(R0,final_keys[1:11]))
    T = xor_bytes(T,AES_modified(R1,final_keys[2:12]))
    T = xor_bytes(T,AES_modified(R2,final_keys[3:13]))
    T = xor_bytes(T,AES_modified(R3,final_keys[4:14]))
    T = xor_bytes(T,AES_modified(R4,final_keys[5:15]))
    
    return AES(nonce_key_2).encrypt_block(T)

if __name__ == "__main__":
    key = [0 for i in range(16)]
    message = [0 for i in range(16)]
    nonce = [0 for i in range(16)]
    printState(key)
    printState(nonce)
    printState(message)
    printState(lemac(key,nonce,message, verbose=True))


    

