# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Ariel Antonitis. Licensed under the MIT license.
#
# nescient/crypto/chacha.pyx
""" Classes and (Cython) functions for working with the ChaCha20 stream cipher.

See RFC 7539 for the cipher specification.
"""
# TODO: Documentation, determine when to multiprocess, implement poly1305 auth tags
from cpython.mem cimport PyMem_Malloc, PyMem_Free

from multiprocessing import cpu_count, Process
from multiprocessing.sharedctypes import RawArray
from ctypes import c_ubyte

from nescient.crypto.tools import randbits


# Little endian bytes to 32-bit words conversion
cdef unsigned int * bytes_to_words(unsigned char * b, unsigned long l):
    cdef unsigned int * w = <unsigned int *>PyMem_Malloc(l)
    cdef unsigned long i
    for i in range(0, l, 4):
        w[i>>2] = b[i] | (b[i+1] << 8) | (b[i+2] << 16) | (b[i+3] << 24)
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

# # Display a bytes object as hex
# def display_hex(data):
#     for i in range(0, len(data), 16):
#         print(' '.join('%02x' % x for x in data[i:i+16]))

# The quarter rounds are currently hard-coded, so this function is not needed.
# # A single ChaCha20 round operating on a state and 4 indices
# cdef quarter_round(unsigned int * x, unsigned char i, unsigned char j, unsigned char k, unsigned char l):
#     x[i] = x[i] + x[j]; x[l] = x[l] ^ x[i]; x[l] = (x[l] << 16) | (x[l] >> 16)
#     x[k] = x[k] + x[l]; x[j] = x[j] ^ x[k]; x[j] = (x[j] << 12) | (x[j] >> 20)
#     x[i] = x[i] + x[j]; x[l] = x[l] ^ x[i]; x[l] = (x[l] << 8) | (x[l] >> 24)
#     x[k] = x[k] + x[l]; x[j] = x[j] ^ x[k]; x[j] = (x[j] << 7) | (x[j] >> 25)

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
        # Quarter round 0, 4, 8, 12
        state[0] = state[0] + state[4]; state[12] = state[12] ^ state[0]; state[12] = (state[12] << 16) | (state[12] >> 16)
        state[8] = state[8] + state[12]; state[4] = state[4] ^ state[8]; state[4] = (state[4] << 12) | (state[4] >> 20)
        state[0] = state[0] + state[4]; state[12] = state[12] ^ state[0]; state[12] = (state[12] << 8) | (state[12] >> 24)
        state[8] = state[8] + state[12]; state[4] = state[4] ^ state[8]; state[4] = (state[4] << 7) | (state[4] >> 25)
        # Quarter round 1, 5, 9, 13
        state[1] = state[1] + state[5]; state[13] = state[13] ^ state[1]; state[13] = (state[13] << 16) | (state[13] >> 16)
        state[9] = state[9] + state[13]; state[5] = state[5] ^ state[9]; state[5] = (state[5] << 12) | (state[5] >> 20)
        state[1] = state[1] + state[5]; state[13] = state[13] ^ state[1]; state[13] = (state[13] << 8) | (state[13] >> 24)
        state[9] = state[9] + state[13]; state[5] = state[5] ^ state[9]; state[5] = (state[5] << 7) | (state[5] >> 25)
        # Quarter round 2, 6, 10, 14
        state[2] = state[2] + state[6]; state[14] = state[14] ^ state[2]; state[14] = (state[14] << 16) | (state[14] >> 16)
        state[10] = state[10] + state[14]; state[6] = state[6] ^ state[10]; state[6] = (state[6] << 12) | (state[6] >> 20)
        state[2] = state[2] + state[6]; state[14] = state[14] ^ state[2]; state[14] = (state[14] << 8) | (state[14] >> 24)
        state[10] = state[10] + state[14]; state[6] = state[6] ^ state[10]; state[6] = (state[6] << 7) | (state[6] >> 25)
        # Quarter round 3, 7, 11, 15
        state[3] = state[3] + state[7]; state[15] = state[15] ^ state[3]; state[15] = (state[15] << 16) | (state[15] >> 16)
        state[11] = state[11] + state[15]; state[7] = state[7] ^ state[11]; state[7] = (state[7] << 12) | (state[7] >> 20)
        state[3] = state[3] + state[7]; state[15] = state[15] ^ state[3]; state[15] = (state[15] << 8) | (state[15] >> 24)
        state[11] = state[11] + state[15]; state[7] = state[7] ^ state[11]; state[7] = (state[7] << 7) | (state[7] >> 25)
        # Quarter round 0, 5, 10, 15
        state[0] = state[0] + state[5]; state[15] = state[15] ^ state[0]; state[15] = (state[15] << 16) | (state[15] >> 16)
        state[10] = state[10] + state[15]; state[5] = state[5] ^ state[10]; state[5] = (state[5] << 12) | (state[5] >> 20)
        state[0] = state[0] + state[5]; state[15] = state[15] ^ state[0]; state[15] = (state[15] << 8) | (state[15] >> 24)
        state[10] = state[10] + state[15]; state[5] = state[5] ^ state[10]; state[5] = (state[5] << 7) | (state[5] >> 25)
        # Quarter round 1, 6, 11, 12
        state[1] = state[1] + state[6]; state[12] = state[12] ^ state[1]; state[12] = (state[12] << 16) | (state[12] >> 16)
        state[11] = state[11] + state[12]; state[6] = state[6] ^ state[11]; state[6] = (state[6] << 12) | (state[6] >> 20)
        state[1] = state[1] + state[6]; state[12] = state[12] ^ state[1]; state[12] = (state[12] << 8) | (state[12] >> 24)
        state[11] = state[11] + state[12]; state[6] = state[6] ^ state[11]; state[6] = (state[6] << 7) | (state[6] >> 25)
        # Quarter round 2, 7, 8, 13
        state[2] = state[2] + state[7]; state[13] = state[13] ^ state[2]; state[13] = (state[13] << 16) | (state[13] >> 16)
        state[8] = state[8] + state[13]; state[7] = state[7] ^ state[8]; state[7] = (state[7] << 12) | (state[7] >> 20)
        state[2] = state[2] + state[7]; state[13] = state[13] ^ state[2]; state[13] = (state[13] << 8) | (state[13] >> 24)
        state[8] = state[8] + state[13]; state[7] = state[7] ^ state[8]; state[7] = (state[7] << 7) | (state[7] >> 25)
        # Quarter round 3, 4, 9, 14
        state[3] = state[3] + state[4]; state[14] = state[14] ^ state[3]; state[14] = (state[14] << 16) | (state[14] >> 16)
        state[9] = state[9] + state[14]; state[4] = state[4] ^ state[9]; state[4] = (state[4] << 12) | (state[4] >> 20)
        state[3] = state[3] + state[4]; state[14] = state[14] ^ state[3]; state[14] = (state[14] << 8) | (state[14] >> 24)
        state[9] = state[9] + state[14]; state[4] = state[4] ^ state[9]; state[4] = (state[4] << 7) | (state[4] >> 25)
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
        # Since this is a stream cipher encryption is the same as decryption
        self.chacha_decrypt = self.chacha_encrypt

    # The function that actually performs ChaCha encryption/decryption
    def _chacha_task(self, data, nonce, count=1):
        # Convert key from bytes to little-endian words
        cdef unsigned int * key_w = bytes_to_words(self.key, 32)
        # Convert the nonce into an array of 32-bit words
        cdef unsigned int * nonce_w = bytes_to_words(nonce.to_bytes(12, byteorder='little'), 12)
        # Initialize counter and working variables
        cdef unsigned int counter = count
        cdef unsigned int n_blocks = <unsigned int>(len(data)//64)
        cdef unsigned char * key_stream
        cdef unsigned char[:] view = data
        cdef unsigned char * buffer = &view[0]
        cdef unsigned int i
        cdef unsigned char j
        for i in range(n_blocks):
            key_stream = chacha20(key_w, nonce_w, counter+i)
            for j in range(64):
                buffer[j] ^= key_stream[j]
            buffer += 64
        i = n_blocks
        if len(data) % 64 != 0:
            key_stream = chacha20(key_w, nonce_w, counter+i)
            for j in range(len(data) % 64):
                buffer[j] ^= key_stream[j]
        return

    def chacha_encrypt(self, data, nonce=None, count=1, force_single_thread=False):
        """ Encrypt (or decrypt) in-memory data using ChaCha20.

        Because the count argument is limited to 32-bits, the most data that can be encrypted at once with this function
        is 256 GiB.

        Since this is a stream cipher, encryption is the same as decryption.

        Args:
            data: Must be either a `bytearray` or some array that is byte-addressable and supports the buffer protocol.
            (byte `RawArray`s are acceptable arguments as well.
            nonce (int): If provided, the 96-bit integer to use as a nonce for this operation. If not provided, a
            random nonce will be generated.
            count (int): The 32-bit counter at which to start the key stream.
            force_single_thread (bool): If `True`, this operation will always run in a single process.

        Returns:
            int: The nonce used in this operation.
        """
        # Generate a random 96-bit nonce if unspecified
        if nonce is None:
            nonce = randbits(96)
        # Determine the number of threads to use based on CPU count
        n_threads = cpu_count()
        # Determine the size of the chunks to use for each thread, and the number of ChaCha blocks per chunk
        chunk_size = len(data)//n_threads//64*64
        blocks_per_chunk = chunk_size//64
        # If forced to use a single thread, or multiprocessing would be slower than a single process,
        # run in a single process
        # TODO: 2**29 bytes = 512 MiB is an artificially set breakpoint for performance; change this
        if force_single_thread or n_threads == 1 or len(data) < 2**29 or blocks_per_chunk == 0:
            self._chacha_task(data, nonce, count)
            return nonce
        # Build the shared arrays to dispatch to workers
        arrays = []
        for i in range(n_threads):
            # The last chunk may be slightly longer if the data is not aligned on chunk boundaries
            if i == n_threads-1:
                x = RawArray(c_ubyte, len(data)-(n_threads-1)*chunk_size)
                memoryview(x).cast('B')[:] = data[(n_threads-1)*chunk_size:]
            else:
                x = RawArray(c_ubyte, chunk_size)
                memoryview(x).cast('B')[:] = data[i*chunk_size:(i+1)*chunk_size]
            arrays.append(x)
        # Initialize each process with the correct array and count arguments
        ps = [Process(target=self._chacha_task, daemon=True,
                      args=(arrays[i], nonce, count+(blocks_per_chunk*i))) for i in range(n_threads)]
        # Start each process, then join them in order
        # TODO: Check for processes raising exceptions
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        # Read the shared arrays back into the data bytearray
        for i in range(n_threads):
            if i == n_threads-1:
                data[(n_threads-1)*chunk_size:] = memoryview(arrays[i]).cast('B')[:]
            else:
                data[i*chunk_size:(i+1)*chunk_size] = memoryview(arrays[i]).cast('B')[:]
        # Delete each shared array, hopefully allowing them to be garbage collected
        for i in range(n_threads):
            del arrays[0]
        return nonce


