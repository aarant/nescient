# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT license.
#
# nescient/test.py
""" Test cases for the various cryptographic algorithms implemented in Nescient. """
import unittest
from random import randint

from nescient.packer import NescientPacker
from nescient.crypto.aes import AesCrypter
from nescient.crypto.tools import get_random_bytes


class AesTest(unittest.TestCase):
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
        data = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a') + bytes.fromhex('ae2d8a571e03ac9c9eb76fac45af8e51') + \
               bytes.fromhex('30c81c46a35ce411e5fbc1191a0a52ef') + bytes.fromhex('f69f2445df4f9b17ad2b417be66c3710')
        data = bytearray(data)
        expected1 = bytes.fromhex('7649abac8119b246cee98e9b12e9197d') + bytes.fromhex('5086cb9b507219ee95db113a917678b2') + \
                    bytes.fromhex('73bed6b8e3c1743b7116e69e22229516') + bytes.fromhex('3ff1caa1681fac09120eca307586e1a7')
        expected2 = data[:]
        crypter.cbc_encrypt(data, implicit=False, iv=iv, do_pad=False)
        self.assertEqual(expected1, data)
        crypter.cbc_decrypt(data, iv=iv, do_pad=False)
        self.assertEqual(expected2, data)

    def test_cbc_vector_2(self):
        key = bytes.fromhex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b')
        crypter = AesCrypter(key)
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        data = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a') + bytes.fromhex('ae2d8a571e03ac9c9eb76fac45af8e51') + \
               bytes.fromhex('30c81c46a35ce411e5fbc1191a0a52ef') + bytes.fromhex('f69f2445df4f9b17ad2b417be66c3710')
        data = bytearray(data)
        expected1 = bytes.fromhex('4f021db243bc633d7178183a9fa071e8') + bytes.fromhex('b4d9ada9ad7dedf4e5e738763f69145a') + \
                    bytes.fromhex('571b242012fb7ae07fa9baac3df102e0') + bytes.fromhex('08b0e27988598881d920a9e64f5615cd')
        expected2 = data[:]
        crypter.cbc_encrypt(data, implicit=False, iv=iv, do_pad=False)
        self.assertEqual(expected1, data)
        crypter.cbc_decrypt(data, iv=iv, do_pad=False)
        self.assertEqual(expected2, data)


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
