# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT license.
#
# nescient/crypto/tools.py
""" Various functions and tools for general cryptographic purposes, like secure randomness, padding, etc. """
try:  # Define a Python-version-independent source of securely random bytes
    import secrets
except ImportError:
    import os

    def get_random_bytes(n):
        return bytes(os.urandom(n))
else:
    def get_random_bytes(n):
        return secrets.token_bytes(n)


def pad(data, block_size):
    """ Pads data to a multiple of the block size in a reversible way, by adding n bytes with value n to the data, where
    n is the number of bytes needed to reach a multiple of the block size.

    Args:
        data: The data to pad to a multiple of the block size. Must be a `bytearray`.
        block_size (int): The desired block size. Must be between 1 and 255 (inclusive).
    """
    assert(1 <= block_size <= 255)
    # Calculate the number of bytes to append
    n = block_size - (len(data) % block_size)
    # Note that, if the data is already a multiple of the block size, a total of block_size bytes will be appended
    data.extend(bytes([n]*n))


def unpad(data):
    """ Unpads data previously padded with `pad`.

    Args:
        data: The data to remove padding from. Must be a `bytearray`. If not previously padded, data may be lost.
    """
    n = data[-1]  # The number of bytes to remove
    del data[-n:]
