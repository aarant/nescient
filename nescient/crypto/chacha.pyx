# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT license.
#
# nescient/crypto/chacha.pyx
""" Classes and (Cython) functions for working with the ChaCha20 stream cipher.

See RFC 7539 for the cipher specification.
"""
# TODO: Hardcore quarter rounds, implement poly1305 auth tags, Documentation
from cpython.mem cimport PyMem_Malloc, PyMem_Free

from nescient.crypto.tools import get_random_bytes


# Little endian bytes to 32-bit words conversion
cdef unsigned int * bytes_to_words(unsigned char * b, unsigned long l):
    cdef unsigned int * w = <unsigned int *>PyMem_Malloc(l)
    cdef unsigned long i
    for i in range(0, l, 4):
        w[i>>2] = b[i] | (b[i+1] << 8) | (b[i+2] << 16) | (b[i+3] << 24)
        #print(i>>2, '%x' % w[i>>2])
    return w

# Little endian 32-bit words to bytes conversion
cdef unsigned char * words_to_bytes(unsigned int * w, unsigned long l):
    cdef unsigned char * b = <unsigned char *>PyMem_Malloc(4*l)
    cdef unsigned long i
    for i in range(l):
        b[4*i] = w[i] & 0xff
        b[4*i+1] = (w[i] >> 8) & 0xff
        b[4*i+2] = (w[i] >> 16) & 0xff
        b[4*i+3] = (w[i] >> 24) & 0xff
    return b

# Display a bytes object as hex
def display_hex(data):
    for i in range(0, len(data), 16):
        print(' '.join('%02x' % x for x in data[i:i+16]))

# A single ChaCha20 round operating on a state and 4 indices
cdef quarter_round(unsigned int * x, unsigned char i, unsigned char j, unsigned char k, unsigned char l):
    x[i] = x[i] + x[j]; x[l] = x[l] ^ x[i]
    x[l] = (x[l] << 16) | (x[l] >> 16)
    x[k] = x[k] + x[l]; x[j] = x[j] ^ x[k]
    x[j] = (x[j] << 12) | (x[j] >> 20)
    x[i] = x[i] + x[j]; x[l] = x[l] ^ x[i]
    x[l] = (x[l] << 8) | (x[l] >> 24)
    x[k] = x[k] + x[l]; x[j] = x[j] ^ x[k]
    x[j] = (x[j] << 7) | (x[j] >> 25)

# Generates 64 keystream bytes from a 256-bit key, a 96-bit nonce, and a 32-bit counter
cdef unsigned char * chacha20(unsigned int * key, unsigned int * nonce, unsigned int count):
    cdef unsigned int state[16]
    cdef unsigned int start_state[16]
    cdef unsigned char i
    # First four words are constants
    state[:4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    # Words 4-11 are the key
    state[4:12] = key
    # Word 12 is the count
    state[12] = count
    # Words 13-15 are the nonce
    state[13:16] = nonce
    # Copy the state into the start state for later
    start_state[:] = state
    # Perform the ChaCha20 rounds
    for i in range(10):
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)
    # Add the original state with the result
    for i in range(16):
        state[i] += start_state[i]
    # Serialize into bytes
    return words_to_bytes(state, 16)

class ChaChaCrypter:
    """ A Crypter object used for encrypting or decrypting arbitrary data using the ChaCha stream cipher.

    Attributes:
        modes (list): A list of cipher modes supported by the algorithm.
        auth (list): A list of authentication modes supported by the algorithm.

    Args:
        key (bytes): The 256 bit key used to encrypt/decrypt data.
    """
    modes = ['stm']  # Represents stream cipher mode
    auth = ['sha']

    def __init__(self, key):
        assert len(key) == 32
        self.key = key[:]
        self.chacha_decrypt = self.chacha_encrypt

    # Encrypt or decrypt arbitrary data with the given key and nonce. Returns the nonce used.
    # Because this is a stream cipher, the encrypt and decrypt functions are the same.
    def chacha_encrypt(self, data, nonce=None, count=1):
        if nonce is None:  # Generate random nonce if unspecified
            nonce = int.from_bytes(get_random_bytes(12), byteorder='little')
        # Convert key from bytes to little-endian words
        cdef unsigned int * key_w = bytes_to_words(self.key, 32)
        # Convert the nonce into an array of 32-bit words
        cdef unsigned int * nonce_w = bytes_to_words(nonce.to_bytes(12, byteorder='little'), 12)
        # Initialize counter and working variables
        cdef unsigned int counter = count
        cdef unsigned int n_blocks = <unsigned int>len(data)//64
        cdef unsigned char * key_stream
        cdef unsigned char * buffer = data
        cdef unsigned int i
        cdef unsigned char j
        for i in range(n_blocks):
            key_stream = chacha20(key_w, nonce_w, counter+i)
            for j in range(64):
                buffer[j] ^= key_stream[j]
            buffer += 64
        i += 1
        if len(data) % 64 != 0:
            key_stream = chacha20(key_w, nonce_w, counter+i)
            for j in range(len(data) % 64):
                buffer[j] ^= key_stream[j]
        return nonce


