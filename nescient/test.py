# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Ariel Antonitis. Licensed under the MIT license.
#
# nescient/test.py
""" Test cases for the various cryptographic algorithms implemented in Nescient. """
import unittest
from random import randint

from nescient.packer import NescientPacker
from nescient.crypto.aes import AesCrypter
from nescient.crypto.chacha import ChaChaCrypter
from nescient.crypto.tools import get_random_bytes


class AesTest(unittest.TestCase):
    # Test vectors are taken from FIPS 197 Appendix C
    # CBC test vectors are taken from NIST Special Publication 800-38a, Appendix F.2
    def test_vector_1(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        crypter = AesCrypter(key)
        data = bytearray.fromhex('00112233445566778899aabbccddeeff')
        expected1 = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
        expected2 = data[:]
        crypter.ecb_encrypt(data, do_pad=False)
        self.assertEqual(expected1, data)
        crypter.ecb_decrypt(data, do_pad=False)
        self.assertEqual(expected2, data)

    def test_vector_2(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617')
        crypter = AesCrypter(key)
        data = bytearray.fromhex('00112233445566778899aabbccddeeff')
        expected1 = bytes.fromhex('dda97ca4864cdfe06eaf70a0ec0d7191')
        expected2 = data[:]
        crypter.ecb_encrypt(data, do_pad=False)
        self.assertEqual(expected1, data)
        crypter.ecb_decrypt(data, do_pad=False)
        self.assertEqual(expected2, data)

    def test_vector_3(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        crypter = AesCrypter(key)
        data = bytearray.fromhex('00112233445566778899aabbccddeeff')
        expected1 = bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')
        expected2 = data[:]
        crypter.ecb_encrypt(data, do_pad=False)
        self.assertEqual(expected1, data)
        crypter.ecb_decrypt(data, do_pad=False)
        self.assertEqual(expected2, data)

    def test_cbc_vector_1(self):
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        crypter = AesCrypter(key)
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        data = bytearray.fromhex('6bc1bee22e409f96e93d7e117393172a'
                                 'ae2d8a571e03ac9c9eb76fac45af8e51'
                                 '30c81c46a35ce411e5fbc1191a0a52ef'
                                 'f69f2445df4f9b17ad2b417be66c3710')
        expected1 = bytes.fromhex('7649abac8119b246cee98e9b12e9197d'
                                  '5086cb9b507219ee95db113a917678b2'
                                  '73bed6b8e3c1743b7116e69e22229516'
                                  '3ff1caa1681fac09120eca307586e1a7')
        expected2 = data[:]
        crypter.cbc_encrypt(data, implicit=False, iv=iv, do_pad=False)
        self.assertEqual(expected1, data)
        crypter.cbc_decrypt(data, iv=iv, do_pad=False)
        self.assertEqual(expected2, data)

    def test_cbc_vector_2(self):
        key = bytes.fromhex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b')
        crypter = AesCrypter(key)
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        data = bytearray.fromhex('6bc1bee22e409f96e93d7e117393172a'
                                 'ae2d8a571e03ac9c9eb76fac45af8e51'
                                 '30c81c46a35ce411e5fbc1191a0a52ef'
                                 'f69f2445df4f9b17ad2b417be66c3710')
        expected1 = bytes.fromhex('4f021db243bc633d7178183a9fa071e8'
                                  'b4d9ada9ad7dedf4e5e738763f69145a'
                                  '571b242012fb7ae07fa9baac3df102e0'
                                  '08b0e27988598881d920a9e64f5615cd')
        expected2 = data[:]
        crypter.cbc_encrypt(data, implicit=False, iv=iv, do_pad=False)
        self.assertEqual(expected1, data)
        crypter.cbc_decrypt(data, iv=iv, do_pad=False)
        self.assertEqual(expected2, data)


class ChaChaTest(unittest.TestCase):
    # Test vectors are taken from RFC 7539 Appendix A.2
    def test_vector_1(self):
        key = bytes([0]*32)
        nonce = 0
        counter = 0
        data = bytearray([0]*64)
        expected1 = bytes.fromhex('76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28'
                                  'bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7'
                                  'da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37'
                                  '6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86')
        expected2 = data[:]
        c = ChaChaCrypter(key)
        c.chacha_encrypt(data, nonce, counter)
        self.assertEqual(expected1, data)
        c.chacha_decrypt(data, nonce, counter)
        self.assertEqual(expected2, data)

    def test_vector_2(self):
        key = bytes([0]*31 + [1])
        nonce = int.from_bytes(bytes([0]*11 + [2]), byteorder='little')
        counter = 1
        data = bytearray('Any submission to the IETF intended by the Contributor for publication as all or part of an '
                         'IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is '
                         'considered an "IETF Contribution". Such statements include oral statements in IETF sessions, '
                         'as well as written and electronic communications made at any time or place, which are '
                         'addressed to', 'utf-8')
        expected1 = bytes.fromhex('a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70'
                                  '41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec'
                                  '2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05'
                                  '0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d'
                                  '40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e'
                                  '20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50'
                                  '42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c'
                                  '68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a'
                                  'd0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66'
                                  '42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d'
                                  'c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28'
                                  'e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b'
                                  '08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f'
                                  'a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c'
                                  'cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84'
                                  'a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b'
                                  'c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0'
                                  '8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f'
                                  '58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62'
                                  'be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6'
                                  '98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85'
                                  '14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab'
                                  '7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd'
                                  'c4 fd 80 6c 22 f2 21')
        expected2 = data[:]
        c = ChaChaCrypter(key)
        c.chacha_encrypt(data, nonce, counter)
        self.assertEqual(expected1, data)
        c.chacha_decrypt(data, nonce, counter)
        self.assertEqual(expected2, data)

    def test_vector_3(self):
        key = bytes.fromhex('1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0'
                            '47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0')
        nonce = int.from_bytes(bytes([0]*11+[2]), byteorder='little')
        counter = 42
        data = bytearray('\'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the '
                         'borogoves,\nAnd the mome raths outgrabe.', 'utf-8')
        expected1 = bytes.fromhex('62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df'
                                  '5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf'
                                  '16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71'
                                  'fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb'
                                  'f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6'
                                  '1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77'
                                  '04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1'
                                  '87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1')
        expected2 = data[:]
        c = ChaChaCrypter(key)
        c.chacha_encrypt(data, nonce, counter)
        self.assertEqual(expected1, data)
        c.chacha_decrypt(data, nonce, counter)
        self.assertEqual(expected2, data)

    # Test vector on data smaller than one block
    def test_vector_4(self):
        key = bytes([153, 5, 91, 169, 17, 217, 190, 176, 31, 234, 240, 251, 223, 248, 116, 134, 11,
                     195, 121, 110, 161, 200, 135, 212, 37, 114, 119, 23, 166, 59, 3, 63])
        nonce = 51494954499285655988572118223
        counter = 1
        data = bytearray([102, 111, 111, 98, 97, 114])
        expected = data[:]
        c = ChaChaCrypter(key)
        c.chacha_encrypt(data, nonce, counter)
        c.chacha_decrypt(data, nonce, counter)
        self.assertEqual(expected, data)


class PackerTest(unittest.TestCase):
    def test_packer(self):
        for _ in range(10):
            password = get_random_bytes(randint(8, 16))
            packer = NescientPacker(password)
            data = bytearray(get_random_bytes(randint(15, 2**20)))
            expected = data[:]
            packer.pack(data)
            self.assertNotEqual(data, expected)
            packer.unpack(data)
            self.assertEqual(data, expected)


if __name__ == '__main__':
    res = unittest.main(verbosity=3, exit=False)
