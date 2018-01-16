# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT license.
#
# nescient/crypto/aes.pyx
""" Classes and (Cython) functions for working with the Advanced Encryption Standard (AES) algorithm in various cipher
modes.

See FIPS 197 for the AES specification.
"""
# TODO: Docstrings, efficiency, CTR mode, GCM mode
from nescient.crypto.galois import GaloisField
from nescient.crypto.tools import get_random_bytes, pad, unpad

GF_FIELD = GaloisField(2, 8, 283, 3)

def make_sboxes():
    """ Generate the AES sbox and inverse sbox from scratch.

    Returns:
        A tuple `(sbox, inv_sbox)` where each is a `bytes` object of length 256, where `b[i]` corresponds to the
    substitution for byte i.
    """
    # Begin with the inverses over GF-256
    sbox = [GF_FIELD.inverse(i) for i in GF_FIELD.f]
    # Perform the affine transformation
    c = 0x63
    for i in range(256):
        b = sbox[i]
        sbox[i] = 0
        for j in range(8):
            sbox[i] ^= ((b >> j & 1) ^ (b >> ((j + 4) % 8) & 1) ^ (b >> ((j + 5) % 8) & 1) ^
                        (b >> ((j + 6) % 8) & 1) ^ (b >> ((j + 7) % 8) & 1) ^ (c >> j & 1)) << j
    inv_sbox = [0]*256
    for i in range(256):
        inv_sbox[sbox[i]] = i  # Map indices to values and vice versa
    return bytes(sbox), bytes(inv_sbox)


def make_mult_lookups():
    return {const: bytes([GF_FIELD.mult(const, i) for i in GF_FIELD.f]) for const in [0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e]}

PY_SBOX, PY_INV_SBOX = make_sboxes()
cdef unsigned char * SBOX = PY_SBOX
cdef unsigned char * INV_SBOX = PY_INV_SBOX

ms = make_mult_lookups()
cdef unsigned char * m2 = ms[0x02]
cdef unsigned char * m3 = ms[0x03]
cdef unsigned char * m9 = ms[0x09]
cdef unsigned char * mB = ms[0x0b]
cdef unsigned char * mD = ms[0x0d]
cdef unsigned char * mE = ms[0x0e]


cdef aes_block_cipher(unsigned char * x, unsigned char * ex_key, unsigned char nr):
    cdef unsigned char j, k, l, r, b0, b1, b2, b3
    # Initial AddRoundKey
    for j in range(16):
        x[j] ^= ex_key[j]
    # For each round
    for r in range(1, nr+1):
        # SubBytes
        for j in range(16):
            x[j] = SBOX[x[j]]
        # ShiftRows
        for j in range(1, 4):
            for k in range(j):
                b = x[j]
                for l in range(0, 12, 4):
                    x[j+l] = x[j+l+4]
                x[j+12] = b
        if r < nr:  # Do MixColumns on all but the last round
            # MixColumns
            for j in range(0, 16, 4):
                b0, b1, b2, b3 = x[j], x[j+1], x[j+2], x[j+3]
                x[j] = m2[b0] ^ m3[b1] ^ b2 ^ b3
                x[j+1] = b0 ^ m2[b1] ^ m3[b2] ^ b3
                x[j+2] = b0 ^ b1 ^ m2[b2] ^ m3[b3]
                x[j+3] = m3[b0] ^ b1 ^ b2 ^ m2[b3]
        # AddRoundKey
        for j in range(16):
            x[j] ^= ex_key[(r << 4)+j]

cdef aes_inv_block_cipher(unsigned char * x, unsigned char * ex_key, unsigned char nr):
    cdef unsigned char j, k, l, r, b0, b1, b2, b3
    for r in range(nr, 0, -1):
        # AddRoundKey
        for j in range(16):
            x[j] ^= ex_key[(r << 4)+j]
        if r < nr:  # Skip InvMixColumns on the last (first when going backwards) round
            # InvMixColumns
            for j in range(0, 16, 4):
                b0, b1, b2, b3 = x[j], x[j+1], x[j+2], x[j+3]
                x[j] = mE[b0] ^ mB[b1] ^ mD[b2] ^ m9[b3]
                x[j+1] = m9[b0] ^ mE[b1] ^ mB[b2] ^ mD[b3]
                x[j+2] = mD[b0] ^ m9[b1] ^ mE[b2] ^ mB[b3]
                x[j+3] = mB[b0] ^ mD[b1] ^ m9[b2] ^ mE[b3]
        # InvShiftRows
        for j in range(1, 4):
            for k in range(j):
                b = x[j+12]
                for l in range(12, -4, -4):
                    x[j+l] = x[j+l-4]
                x[j] = b
        # InvSubBytes
        for j in range(16):
            x[j] = INV_SBOX[x[j]]
    # Initial AddRoundKey
    for j in range(16):
        x[j] ^= ex_key[j]


class AesCrypter:
    """ A Crypter object used for encrypting or decrypting arbitrary data using AES in various modes.

    Attributes:
        modes (list): A list of cipher modes supported by the algorithm.
        auth (list): A list of authentication modes supported by the algorithm.

    Args:
        key (bytes): The 128, 192, or 256 bit key to use to encrypt/decrypt data, as a `bytes` object.
    """
    gf = GF_FIELD
    sbox, inv_sbox = PY_SBOX, PY_INV_SBOX
    modes = ['cbc']
    auth = ['sha']

    def __init__(self, key):
        self.key = key[:]
        assert len(self.key) in [16, 24, 32]
        # Initialize constants
        self.nb = 4  # Fixed in the FIPS spec
        self.nk = len(self.key) // 4
        self.nr = self.nk + 6  # The number of rounds
        # Perform the key expansion
        self.key_expansion()

    def key_expansion(self):
        # Generate rcon table (only 15 elements--powers of 2 in GF-256)
        sbox = self.__class__.sbox
        rcon = [0x01]*15
        for i in range(1, 15):
            rcon[i] = GF_FIELD.mult(rcon[i-1], 0x02)
        # Allocate memory for the expanded key and copy the initial key into it
        self.ex_key = bytearray(4*self.nb*(self.nr+1))
        self.ex_key[:len(self.key)] = self.key[:]
        for i in range(self.nk, self.nb*(self.nr+1)):
            j = i-1
            b0, b1, b2, b3 = self.ex_key[4*j], self.ex_key[4*j+1], self.ex_key[4*j+2], self.ex_key[4*j+3]
            if i % self.nk == 0:
                b = b0
                b0 = sbox[b1] ^ rcon[i // self.nk - 1]
                b1, b2, b3 = sbox[b2], sbox[b3], sbox[b]
            elif self.nk == 8 and (i % self.nk) == 4:
                b0, b1, b2, b3 = sbox[b0], sbox[b1], sbox[b2], sbox[b3]
            self.ex_key[4*i] = b0 ^ self.ex_key[4*(i - self.nk)]
            self.ex_key[4*i+1] = b1 ^ self.ex_key[4*(i - self.nk)+1]
            self.ex_key[4*i+2] = b2 ^ self.ex_key[4*(i - self.nk)+2]
            self.ex_key[4*i+3] = b3 ^ self.ex_key[4*(i - self.nk)+3]
        self.ex_key = bytes(self.ex_key)

    def ecb_encrypt(self, data, do_pad=True):
        if do_pad: # Pad the data to a 16 byte block size
            pad(data, 16)
        # Initialize C constants for speed
        cdef unsigned long long length = len(data)
        assert(length % 16 == 0)
        cdef unsigned long long i
        cdef unsigned char * buffer = data
        cdef unsigned char * ex_key = self.ex_key
        cdef unsigned char nr = self.nr
        # Cipher each 16-byte block
        for i in range(0, length, 16):
            aes_block_cipher(buffer, ex_key, nr)
            buffer += 16

    def ecb_decrypt(self, data, do_pad=True):
        # Initialize C constants for speed
        cdef unsigned long long length = len(data)
        assert(length % 16 == 0)
        cdef unsigned char * buffer = data
        cdef unsigned char * ex_key = self.ex_key
        cdef unsigned char nr = self.nr
        # Cipher each 16-byte block
        for i in range(0, length, 16):
            aes_inv_block_cipher(buffer, ex_key, nr)
            buffer += 16
        if do_pad: # Unpad the previously padded data
            unpad(data)

    def cbc_encrypt(self, data, implicit=True, iv=None, do_pad=True):
        if do_pad: # Pad the data to a 16 byte block size
            pad(data, 16)
        # Initialize C constants for speed
        cdef unsigned long long length = len(data)
        assert(length % 16 == 0)
        cdef unsigned long long i
        cdef unsigned char * ex_key = self.ex_key
        cdef unsigned char nr = self.nr
        cdef unsigned char j
        if iv is None:  # Generate a random initialization vector, otherwise use the IV passed in
            iv = get_random_bytes(16)
        if implicit:
            # Prepend a random block to the message, so that the IV doesn't have to be stored for decryption
            data[:] = bytearray(get_random_bytes(16)) + data
        # Xor the first block with the IV and encrypt
        cdef unsigned char * buffer = data
        length = len(data)
        for j in range(16):
            buffer[j] ^= iv[j]
        aes_block_cipher(buffer, ex_key, nr)
        buffer += 16
        for i in range(16, length, 16):  # Feed each ciphered block into the next
            for j in range(16):
                buffer[j] ^= buffer[j-16]
            aes_block_cipher(buffer, ex_key, nr)
            buffer += 16


    def cbc_decrypt(self, data, iv=None, do_pad=True):
        # Initialize C constants
        cdef unsigned long long length = len(data)
        assert(length % 16 == 0)
        cdef unsigned long long i
        cdef unsigned char * ex_key = self.ex_key
        cdef unsigned char nr = self.nr
        cdef unsigned char j
        cdef unsigned char * buffer = data
        buffer += length-16
        for i in range(length-16, 0, -16):
            # Inverse cipher the block, then xor it with the previous one
            aes_inv_block_cipher(buffer, ex_key, nr)
            for j in range(16):
                buffer[j] ^= buffer[j-16]
            buffer -= 16
        if iv:  # If provided an iv, the first block contains meaningful data and we should decrypt it
            aes_inv_block_cipher(buffer, ex_key, nr)
            for j in range(16):
                buffer[j] ^= iv[j]
        else:  # Otherwise assume it is implicit and slice off the first 16 bytes
            del data[:16]
        if do_pad: # Unpad the previously padded data
            unpad(data)




