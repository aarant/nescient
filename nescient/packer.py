# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT license.
#
# nescient/packer.py
""" The Packer class, used to pack and unpack Nescient containers, as well as packer-specific exceptions. """
# TODO: Documentation, version handling
import os
import hmac  # Generating authentication tags with SHA-2 # TODO: Re-implement this in Cython
from contextlib import ExitStack
from hashlib import pbkdf2_hmac  # PBKDF2 Key derivation # TODO: Re-implement this in Cython
from timeit import default_timer as timer

from nescient import __version__, version_to_tuple, newer_version, NescientError
from nescient.timing import load_benchmarks, write_benchmarks
from nescient.crypto.tools import get_random_bytes
from nescient.crypto.aes import AesCrypter
from nescient.crypto.chacha import ChaChaCrypter


class PackingError(NescientError):
    pass


class ParamError(PackingError):
    """ Signifies that invalid parameters were specified """
    pass


class AuthError(PackingError):
    """ Signifies that the data was not authenticated properly """
    pass


# A mapping between supported algorithms, their crypter classes and key sizes in bytes
SUPPORTED_ALGS = {'aes128': (AesCrypter, 16), 'aes192': (AesCrypter, 24), 'aes256': (AesCrypter, 32),
                  'chacha': (ChaChaCrypter, 32)}


class NescientPacker:
    """ Packer/Unpacker for Nescient containers

    Args:
        password: The password to encrypt/decrypt with. Must be a `str` or `bytes` object
        alg (str): A 6 character string specifying the algorithm to use for packing. Must exist in `SUPPORTED_ALGS`.
        mode (str): A 3 character string specifying the cipher mode of operation. Currently only `'cbc'` is supported.
        auth (str): A 3 character string specifying the cipher mode of operation. Currently only `'sha'` is supported.

    Attributes:
        times: Either a dictionary with file sizes as keys and a list of benchmarked packing times as values, or,
            if no benchmarking data is available for the packer's settings, `None`.
    """
    def __init__(self, password, alg='chacha', mode='stm', auth='sha'):
        # password must be a bytes object in order to work with the key generation, so convert it
        if type(password) is str:
            self.password = bytes(password, 'utf-8')
        elif type(password is bytes):
            self.password = password
        else:
            raise ParamError('Password is not of proper type (string or bytes)')
        # Ensure the algorithm selected is supported
        if alg not in SUPPORTED_ALGS:
            raise ParamError('Unsupported algorithm: %s' % alg)
        self.CrypterClass, self.key_len = SUPPORTED_ALGS[alg]
        # Ensure the algorithm supports the cipher and auth modes
        if mode not in self.CrypterClass.modes:
            raise ParamError('Cipher mode %s is unsupported by algorithm' % mode)
        if auth not in self.CrypterClass.auth:
            raise ParamError('Authentication mode %s is unspported by algorithm' % auth)
        self.alg, self.mode, self.auth = alg, mode, auth
        # Supported authenticated encryption protocols. TODO: Only SHA-256 is supported right now
        if auth == 'sha':
            self._gen_auth_tag = lambda key, auth_data, enc_data: hmac.new(key, auth_data + enc_data,
                                                                           digestmod='sha256').digest()
        # Attempt to load benchmark data for the specified settings
        self.times = load_benchmarks().get(self.alg + self.mode + self.auth)

    # Fix out paths depending on the packing choice and the output path
    @staticmethod
    def fix_out_path(in_path, out_path, packing_choice):
        directory, basename = os.path.split(in_path)
        if packing_choice == 'pack':
            if out_path is None:  # Just append .nesc
                return in_path + '.nesc'
            elif os.path.isdir(out_path):  # Pack to a different directory and append .nesc
                return os.path.join(out_path, basename + '.nesc')
            else:
                return out_path  # Directly pack to the requested path
        else:  # packing_choice == 'unpack'
            root, ext = os.path.splitext(basename)
            if ext == '.nesc':  # Strip the .nesc extension, if any
                in_path = in_path[:-5]
                basename = basename[:-5]
            if out_path is None:  # Unpack to the same directory
                return in_path
            elif os.path.isdir(out_path):  # Unpack to another directory
                return os.path.join(out_path, basename)
            else:  # Directly unpack to the requested path
                return out_path

    # Performs PBKDF2 key derivation with a specified salt
    def _key_gen(self, salt):
        return pbkdf2_hmac('sha256', self.password, salt, 100000, self.key_len)

    # Encrypts an arbitrary block of data, modifying it in place and returning the key and salt used
    def _encrypt(self, data, key=None, salt=None):
        if key is None or salt is None:
            salt = get_random_bytes(16)  # Generate a random 16 byte salt
            key = self._key_gen(salt)
        # Build a new crypter object
        crypter = self.CrypterClass(key)
        if isinstance(crypter, ChaChaCrypter):
            # Use the first 12 bytes of the salt as the nonce
            nonce = int.from_bytes(salt[:12], byteorder='little')
            crypter.chacha_encrypt(data, nonce)
        elif isinstance(crypter, AesCrypter):
            getattr(crypter, self.mode + '_encrypt')(data)
        return key, salt

    # Decrypts data, using the specified key
    def _decrypt(self, data, key, salt):
        crypter = self.CrypterClass(key)
        if isinstance(crypter, ChaChaCrypter):
            # Use the first 12 bytes of the salt as the nonce
            nonce = int.from_bytes(salt[:12], byteorder='little')
            crypter.chacha_encrypt(data, nonce)
        elif isinstance(crypter, AesCrypter):
            getattr(crypter, self.mode + '_decrypt')(data)

    def pack(self, data):
        """ Pack data into an in-memory Nescient container in place.

        Args:
            data: The bytearray representing the data.
        """
        # Generate and verify 24 byte Nescient header
        version_tuple = version_to_tuple(__version__)[:3]
        header = bytearray('NESC' + '%02d.%02d.%02d' % version_tuple + self.alg + self.mode + self.auth, 'utf-8')
        if len(header) != 24:
            raise PackingError('Invalid Nescient header ' + str(header, 'utf-8'))
        # Encrypt-then-MAC the data
        key, salt = self._encrypt(data)
        auth_tag = self._gen_auth_tag(key, header + salt, data)
        # Prepend the header, salt, and auth_tag to the data
        data[:] = header + salt + auth_tag + data

    def pack_or_unpack_file(self, in_path, out_path, packing_choice, overwrite=True):
        with ExitStack() as stack:
            f_in = stack.enter_context(open(in_path, 'rb'))
            data = bytearray(os.path.getsize(in_path))
            f_in.readinto(data)
            if packing_choice == 'pack':
                self.pack(data)
            else:
                self.unpack(data)
            # Close the file descriptor
            stack.close()
            if overwrite:
                f_out = stack.enter_context(open(in_path, 'wb'))
                f_out.write(data)
                stack.close()
                os.replace(in_path, out_path)
            else:
                f_out = stack.enter_context(open(out_path, 'wb'))
                f_out.write(data)

    def unpack(self, data):
        """ Unpack an in-memory Nescient container in place.

        Args:
            data: The bytearray representing the Nescient container.
        """
        if len(data) < 24:  # Must have at least 24 header bytes
            raise PackingError('Not a valid Nescient container')
        header = data[:24]
        if header[0:4] != b'NESC':  # Check for a valid header
            raise PackingError('Invalid Nescient header')
        # packed_version = str(header[4:12], 'utf-8')
        # if newer_version(__version__, packed_version) == 2:  # If the packed version is newer, warn the user
        #     warn('Packed version', packed_version, 'is newer than current; may be unable to unpack.')
        alg, mode, auth = str(header[12:18], 'utf-8'), str(header[18:21], 'utf-8'), str(header[21:24], 'utf-8')
        # Initialize a temporary unpacker with file settings
        temp_unpacker = NescientPacker(self.password, alg, mode, auth)
        # Grab the salt and authenticate the data
        if len(data) < 40:  # Must have at least 16 salt bytes
            raise PackingError('Container is missing salt')
        salt = data[24:40]
        if auth == 'sha':
            if len(data) < 72:  # Must have at least 32 auth_tag bytes
                raise PackingError('Container is missing auth tag')
            auth_tag = data[40:72]
            data[:] = data[72:]  # 24 header bytes, 16 salt bytes and 32 auth_tag bytes == 72
            key = temp_unpacker._key_gen(salt)
            new_auth_tag = temp_unpacker._gen_auth_tag(key, header + salt, data)
            if not hmac.compare_digest(auth_tag, new_auth_tag):
                raise AuthError('Authentication tags not equal! The file is corrupt, tampered with, '
                                'or the password is incorrect.')
            temp_unpacker._decrypt(data, key, salt)

    def benchmark(self):
        """ Generate and write new benchmarks for the packer's settings. """
        if self.times is None:
            self.times = {}
        for size in [2**x for x in range(10, 35, 5)]:
            self.times[size] = []
            data = bytearray(size)
            # Calculate key generation rate
            start = timer()
            checkpoint = timer()
            salt = get_random_bytes(16)
            key = self._key_gen(salt)
            self.times[size].append(timer() - checkpoint)
            # Calculate encryption rate
            checkpoint = timer()
            self._encrypt(data, key, salt)
            self.times[size].append(timer() - checkpoint)
            # Calculate authentication rate
            checkpoint = timer()
            self._gen_auth_tag(key, bytearray(24) + salt, data)
            self.times[size].append(timer() - checkpoint)
            # Calculate total rate
            self.times[size].append(timer() - start)
            print(size, self.times[size])  # TODO: Debug
        write_benchmarks(self.alg + self.mode + self.auth, self.times)
