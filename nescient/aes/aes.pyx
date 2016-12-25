"""
PyAES 1.0
Pure-Python standalone implementation of the AES (Advanced Encryption Standard)
Supports 128, 192, and 256 bit keys in CBC (Cipher-Block-Chaining) mode
Computes sboxes and lookup tables on-the-fly
"""
import os  # For random IV's

from .galois import GaloisField  # Finite field implementation


class AesCrypter:
    """
    AesCrypter class, used to encrypt arbitrary blocks of data with the AES algorithm

    Given a proper key (bytes object of certain length), encrypts or decrypts data
    """
    gf = GaloisField(2, 8, 283, 3)  # Rjindael's finite field
    isInitialized = False  # Used to signal that certain attributes must be initialized for the first time

    def __init__(self, key, mode='cbc'):
        # Initialize the class variables for the first time
        if not self.__class__.isInitialized:
            self.__class__.firstInit()
        self.key = key[:]  # Copy the key
        assert len(self.key) == 16 or len(self.key) == 24 or len(self.key) == 32
        # Initialize constants
        self.nb = 4
        self.nk = len(self.key) // 4
        self.nr = self.nk + 6
        self.rounds = range(1, self.nr+1)
        self.mode = mode
        if mode == 'cbc':
            self.encrypt = self.CbcEncrypt
            self.decrypt = self.CbcDecrypt
        # Perform the key expansion
        self.exKey = self.keyExpansion()

    # Initializes sboxes and other fast lookup tables
    @classmethod
    def firstInit(cls):
        # Precompute S-boxes
        cls.sbox, cls.invSbox = cls.makeSboxes()
        # For quick lookup in mixColumns
        cls.m2 = [cls.gf.mult(0x02, i) for i in cls.gf.f]
        cls.m3 = [cls.gf.mult(0x03, i) for i in cls.gf.f]
        cls.m9 = [cls.gf.mult(0x09, i) for i in cls.gf.f]
        cls.mB = [cls.gf.mult(0x0b, i) for i in cls.gf.f]
        cls.mD = [cls.gf.mult(0x0d, i) for i in cls.gf.f]
        cls.mE = [cls.gf.mult(0x0e, i) for i in cls.gf.f]
        cls.isInitialized = True

    # Generates the Rjindael sbox and inverse sbox
    @classmethod
    def makeSboxes(cls):
        # Begin with the inverses over GF-256
        sbox = [cls.gf.inverse(i) for i in cls.gf.f]
        # Perform the affine transformation
        c = 0x63
        for i in range(256):
            b = sbox[i]
            sbox[i] = 0
            for j in range(8):
                sbox[i] ^= ((b >> j & 1) ^ (b >> ((j + 4) % 8) & 1) ^ (b >> ((j + 5) % 8) & 1) ^
                            (b >> ((j + 6) % 8) & 1) ^ (b >> ((j + 7) % 8) & 1) ^ (c >> j & 1)) << j
        sbox = bytearray(sbox)
        invSbox = bytearray(256)
        for i in range(256): invSbox[sbox[i]] = i  # Map indices to values and vice versa
        return sbox, invSbox

    # Performs the key expansion
    def keyExpansion(self):
        # Generate rcon table (only 15 elements -- powers of 2 in GF-256)
        rcon = [0x01] * 15
        for i in range(1, 15): rcon[i] = self.gf.mult(rcon[i - 1], 0x02)
        # Allocate memory for the expanded key, and copy the key into it
        exKey = bytearray(4*self.nb*(self.nr+1))
        for i in range(len(self.key)):
            exKey[i] = self.key[i]
        # Perform the key expansion, operating on a sliding window of words
        for i in range(self.nk, self.nb*(self.nr+1)):
            j = i - 1  # Clearer
            b0 = exKey[4*j]
            b1 = exKey[4*j+1]
            b2 = exKey[4*j+2]
            b3 = exKey[4*j+3]
            if i % self.nk == 0:
                b = b0
                b0 = self.sbox[b1] ^ rcon[i//self.nk - 1]
                b1 = self.sbox[b2]
                b2 = self.sbox[b3]
                b3 = self.sbox[b]
            elif self.nk == 8 and (i % self.nk) == 4:
                b0 = self.sbox[b0]
                b1 = self.sbox[b1]
                b2 = self.sbox[b2]
                b3 = self.sbox[b3]
            exKey[4*i] = b0 ^ exKey[4*(i-self.nk)]
            exKey[4*i+1] = b1 ^ exKey[4*(i-self.nk)+1]
            exKey[4*i+2] = b2 ^ exKey[4*(i-self.nk)+2]
            exKey[4*i+3] = b3 ^ exKey[4*(i-self.nk)+3]
        return exKey

    # XORS the nth round key with the state starting at index i
    def addRoundKey(self, state, i, n):
        n *= 16
        for j in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]:
            state[i+j] ^= self.exKey[n + j]

    # Performs subBytes on the state starting at index i
    @classmethod
    def subBytes(cls, state, i):
        for j in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]:
            state[i+j] = cls.sbox[state[i+j]]

    # Performs shiftRows on the state starting at index i
    @staticmethod
    def shiftRows(state, i):
        for j in [1, 2, 3]:
            for k in range(j):
                b = state[i+j]
                for l in [0, 4, 8]:
                    state[i+j+l] = state[i+j+l+4]
                state[i+j+12] = b

    # Performs mixColumns on the state starting at index i
    @classmethod
    def mixColumns(cls, state, i):
        for j in [0, 4, 8, 12]:
            b0 = i + j
            b1 = b0 + 1
            b2 = b1 + 1
            b3 = b2 + 1
            a = cls.m2[state[b0]] ^ cls.m3[state[b1]] ^ state[b2] ^ state[b3]
            b = state[b0] ^ cls.m2[state[b1]] ^ cls.m3[state[b2]] ^ state[b3]
            c = state[b0] ^ state[b1] ^ cls.m2[state[b2]] ^ cls.m3[state[b3]]
            d = cls.m3[state[b0]] ^ state[b1] ^ state[b2] ^ cls.m2[state[b3]]
            state[b0] = a
            state[b1] = b
            state[b2] = c
            state[b3] = d

    # Inverse mixColumns
    @classmethod
    def invMixColumns(cls, state, i):
        for j in [0, 4, 8, 12]:
            b0 = i + j
            b1 = b0 + 1
            b2 = b1 + 1
            b3 = b2 + 1
            a = cls.mE[state[b0]] ^ cls.mB[state[b1]] ^ cls.mD[state[b2]] ^ cls.m9[state[b3]]
            b = cls.m9[state[b0]] ^ cls.mE[state[b1]] ^ cls.mB[state[b2]] ^ cls.mD[state[b3]]
            c = cls.mD[state[b0]] ^ cls.m9[state[b1]] ^ cls.mE[state[b2]] ^ cls.mB[state[b3]]
            d = cls.mB[state[b0]] ^ cls.mD[state[b1]] ^ cls.m9[state[b2]] ^ cls.mE[state[b3]]
            state[b0] = a
            state[b1] = b
            state[b2] = c
            state[b3] = d

    # Inverse shiftRows
    @staticmethod
    def invShiftRows(state, i):
        for j in [1, 2, 3]:
            for k in range(j):
                b = state[i+j+12]
                for l in [12, 8, 4]:
                    state[i+j+l] = state[i+j+(l-4)]
                state[i+j] = b

    # Inverse subBytes
    @classmethod
    def invSubBytes(cls, state, i):
        for j in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]:
            state[i+j] = cls.invSbox[state[i+j]]

    # Ciphers a 16-byte block considered to begin at index i
    def blockCipher(self, state, i=0):
        self.addRoundKey(state, i, 0)  # Initial addRoundKey
        for j in self.rounds:
            self.__class__.subBytes(state, i)
            self.shiftRows(state, i)
            if j < self.nr:  # Skip mixColumns on the last round
                self.__class__.mixColumns(state, i)
            self.addRoundKey(state, i, j)
        return

    # Inverse ciphers a 16-byte block considered to begin at index i
    def invBlockCipher(self, state, i=0):
        for j in reversed(self.rounds):
            self.addRoundKey(state, i, j)
            if j < self.nr:  # Skip mixColumns on the last round
                self.__class__.invMixColumns(state, i)
            self.invShiftRows(state, i)
            self.__class__.invSubBytes(state, i)
        self.addRoundKey(state, i, 0)  # Initial addRoundKey

    # Pads data of any length to a multiple of 16 bytes
    def pad(self, data):
        padLen = 16 - (len(data) % 16)  # Add an entire block if the data is already a multiple of 16
        padding = bytearray([padLen] * padLen)
        data.extend(padding)

    # Depads data to its original length, assuming the pad method used
    def dePad(self, data):
        padLen = data[-1]
        del data[-padLen:]

    # Xors block starting at index j into dest starting at index i
    def xorBlock(self, dest, i, block, j):
        for k in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]:
            dest[i+k] ^= block[j+k]

    def CbcEncrypt(self, input):  # TODO: Include block cipher logic here
        """ Encrypts data in CBC mode """
        iv = bytearray([os.urandom(1)[0] for i in range(16)])  # Generate a random initialization vector
        output = bytearray([os.urandom(1)[0] for i in range(16)])  # Generate a random block to prepend to the message, to avoid disseminating IV
        self.pad(input)  # Pad the input
        output.extend(input)  # Copy it into the output buffer
        self.xorBlock(output, 0, iv, 0)  # Initial xor and cipher with the IV
        self.blockCipher(output, 0)
        for i in range(16, len(output), 16):  # Feed each ciphered block into the next
            self.xorBlock(output, i, output, i - 16)
            self.blockCipher(output, i)
        return output

    def CbcDecrypt(self, input):
        """ Decrypts data in CBC mode """
        output = input[:]  # Copy the input into the output buffer
        for i in range(len(output) - 16, 0, -16):
            self.invBlockCipher(output, i)
            self.xorBlock(output, i, output, i - 16)
        del output[:16]  # Remove the first block, which was just random
        self.dePad(output)  # Depad to get the original input
        return output

# print(''.join('%02x' % b for b in header))  # Print a bytes object as hex

# class AesTest:
#     def __init__(self):
#         self.tests = [self.c1, self.c2, self.c3]
#
#     @staticmethod
#     def assertEqual(data1, data2):
#         for b1, b2 in zip(data1, data2):
#             if b1 != b2:
#                 return False
#         return True
#
#     def all(self):
#         for testFunc in self.tests:
#             testFunc()
#
#     def c1(self):
#         print('C.1 AES-128:')
#         key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
#         data = bytearray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
#         expected = bytes([0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a])
#         print('Key: ' + ''.join('%02x' % b for b in key))
#         print('Plaintext: ' + ''.join('%02x' % b for b in data))
#         print('Expected: ' + ''.join('%02x' % b for b in expected))
#         crypter = AesCrypter(key)
#         crypter.blockCipher(data)
#         print('Result: ' + ''.join('%02x' % b for b in data))
#         if self.assertEqual(data, expected):
#             print('Test passed')
#             return True
#         else:
#             print('!!Test result does not match expected value!!')
#             return False
#
#     def c2(self):
#         print('C.2 AES-192:')
#         key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
#                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
#         data = bytearray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
#         expected = bytes([0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91])
#         print('Key: ' + ''.join('%02x' % b for b in key))
#         print('Plaintext: ' + ''.join('%02x' % b for b in data))
#         print('Expected: ' + ''.join('%02x' % b for b in expected))
#         crypter = AesCrypter(key)
#         crypter.blockCipher(data)
#         print('Result: ' + ''.join('%02x' % b for b in data))
#         if self.assertEqual(data, expected):
#             print('Test passed')
#             return True
#         else:
#             print('!!Test result does not match expected value!!')
#             return False
#
#     def c3(self):
#         print('C.3 AES-256:')
#         key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
#                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f])
#         data = bytearray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
#         expected = bytes([0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89])
#         print('Key: ' + ''.join('%02x' % b for b in key))
#         print('Plaintext: ' + ''.join('%02x' % b for b in data))
#         print('Expected: ' + ''.join('%02x' % b for b in expected))
#         crypter = AesCrypter(key)
#         crypter.blockCipher(data)
#         print('Result: ' + ''.join('%02x' % b for b in data))
#         if self.assertEqual(data, expected):
#             print('Test passed')
#             return True
#         else:
#             print('!!Test result does not match expected value!!')
#             return False
#
# t = AesTest()
# t.all()
