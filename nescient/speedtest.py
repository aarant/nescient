import gc

from nescient.crypto.chacha import ChaChaCrypter
from timeit import default_timer as timer

if __name__ == '__main__':
    crypter = ChaChaCrypter(bytes(32))
    for d in [2**x for x in range(20, 31)]:
        for x in [False, True]:
            data = bytearray(d)
            start = timer()
            nonce = crypter.chacha_encrypt(data, force_single_thread=x)
            now = timer()
            print(d/2**20, round((d/2**20)/(now-start), 2), 'MiB/s (%s)' % ('single' if x else 'multi'))
            del data
            gc.collect()
    input()