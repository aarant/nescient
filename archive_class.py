import sys
import hmac
import locale
import codecs
from zipfile import ZipFile

from nescient.packer import NescientPacker
from nescient.crypto.chacha import ChaChaCrypter

print = lambda *args, **kw: None

class NescientArchive:
    def _gen_auth_tag(self, key, auth_data, fp, chunk_size=2**29):
        hmac_obj = hmac.new(key, auth_data, digestmod='sha256')
        self.fp.seek(72, 0)
        i = 0
        while True:
            chunk = fp.read(chunk_size)
            i += 1
            if len(chunk) == 0:
                print('Read %04d chunks' % i)
                break
            else:
                print('Read %04d chunks' % i, end='\r')
            hmac_obj.update(chunk)
        return hmac_obj.digest()
        
    def __init__(self, filename, password, mode='rb', encoding=None):
        self.mode = mode
        self.encoding = locale.getpreferredencoding(False) if encoding is None else encoding
        parsed = NescientPacker.parse_nescient_header(filename)
        header, alg, packing_mode, auth, salt, auth_tag = [parsed[name] for name in ['header', 'alg', 'mode', 'auth', 'salt', 'auth_tag']]
        self.fp = open(filename, 'rb')
        self.fp.seek(0, 2)
        self.needle = 0
        self.file_size = self.fp.tell()-72
        packer = NescientPacker(password, alg, packing_mode, auth)
        self.key = packer._key_gen(salt)
        self.crypter = ChaChaCrypter(self.key)
        self.nonce = int.from_bytes(salt[:12], byteorder='little')
        new_auth_tag = self._gen_auth_tag(self.key, header + salt, self.fp)
        if not hmac.compare_digest(auth_tag, new_auth_tag):
            raise Exception('Authentication tags not equal')

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.fp.close()

    def seek(self, offset, whence=0):
        if whence == 0:
            self.needle = offset
        elif whence == 1:
            self.needle += offset
        else:
            self.needle = self.file_size + offset
        print('Seek:', offset, whence, self.needle)

    def tell(self):
        return self.needle

    def close(self):
        self.fp.close()

    def read(self, size=-1):
        print('Read:', size)
        # Determine what block the needle is in
        block, offset = divmod(self.needle, 64)
        print('Block: %s Offset: %s' % (block, offset))
        self.fp.seek(block*64+72, 0)
        print('Seeking to:', block*64+72)
        data = bytearray(self.fp.read(-1 if size == -1 else size+offset))
        if len(data) > 0:
            self.crypter.chacha_encrypt(data, self.nonce, block+1)
            data[:] = data[offset:]
        data = bytes(data)
        if self.mode == 'r':
            return codecs.decode(data, encoding=self.encoding)
        else:
            self.needle += len(data)
            return data

if __name__ == '__main__':
    filename = 'Content.zip.nesc'
    password = input('Password: ')
    with open('Content.zip', 'rb') as f:
        f.seek(0, 2)
        print(f.tell())
        f.seek(-22, 2)
        print(f.tell())
        b = f.read()
        print(b, len(b))
    with NescientArchive(filename, password, 'rb') as f:
        with ZipFile(f) as z:
            names = z.namelist()
            print('Opening')
            with z.open(names[0]) as f2:
                b = f2.read()
                print(len(b))
            print(z.extract(names[0]))
        
