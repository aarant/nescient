from libc.stdint cimport uint8_t, uint32_t, uint64_t

cdef void _chacha_task(uint32_t * key_w, uint8_t * data, uint32_t * nonce_w, uint32_t count,
                       uint64_t l) nogil