import os
import hmac
import locale
import codecs
from zipfile import ZipFile, BadZipFile

from nescient.packer import NescientPacker, AuthError, ParamError
from nescient.crypto.chacha import ChaChaCrypter

# TODO: AES encryption


class SingleFileArchive:  # Dummy class for single file archives
    def __init__(self, outer, filename):
        self.outer = outer
        if filename[-5:] == '.nesc':
            self.filename = filename[:-5]
        else:
            self.filename = filename

    def __enter__(self, *args, **kwargs):
        return self

    def __exit__(self, *args, **kwargs):
        return self

    def open(self, *args, **kwargs):
        return self

    def seek(self, *args, **kwargs):
        return self.outer.seek(*args, **kwargs)

    def tell(self, *args, **kwargs):
        return self.outer.tell(*args, **kwargs)

    def close(self, *args, **kwargs):
        return None

    def read(self, *args, **kwargs):
        return self.outer.read(*args, **kwargs)


class NescientArchive:  # Represents a Nescient archive as a file-like object
    def _gen_auth_tag(self, key, auth_data, fp, chunk_size=2**29):
        hmac_obj = hmac.new(key, auth_data, digestmod='sha256')
        self.fp.seek(72, 0)
        i = 0
        while True:
            chunk = fp.read(chunk_size)
            i += 1
            if len(chunk) == 0:
                break
            hmac_obj.update(chunk)
        return hmac_obj.digest()
        
    def __init__(self, filename, password, mode='rb', encoding=None):
        self.file_mode = mode
        self.filename = filename
        self.encoding = locale.getpreferredencoding(False) if encoding is None else encoding
        parsed = NescientPacker.parse_nescient_header(filename)
        header, self.alg, self.mode, self.auth, salt, auth_tag = \
            [parsed[name] for name in ('header', 'alg', 'mode', 'auth', 'salt', 'auth_tag')]
        self.packing_mode = self.alg + '-' + self.mode + '-' + self.auth  # Full hyphenated packing mode
        if self.packing_mode != 'chacha-stm-sha':  # TODO: Other packing modes
            raise ParamError('Mode {} is not yet supported.'.format(self.packing_mode))
        self.fp = open(filename, 'rb')
        self.fp.seek(0, 2)
        self.needle = 0
        self.file_size = self.fp.tell()-72
        packer = NescientPacker(password, self.alg, self.mode, self.auth)
        self.key = packer._key_gen(salt)
        self.crypter = ChaChaCrypter(self.key)
        self.nonce = int.from_bytes(salt[:12], byteorder='little')
        new_auth_tag = self._gen_auth_tag(self.key, header + salt, self.fp)
        if not hmac.compare_digest(auth_tag, new_auth_tag):
            raise AuthError('Authentication tags not equal!')
        try:
            self.inner = ZipFile(self, 'r')
        except BadZipFile:
            self.inner = SingleFileArchive(self, filename)

    def open(self, *args, **kwargs):
        return self.inner.open(*args, **kwargs)

    def close(self):
        self.fp.close()

    def seek(self, offset, whence=0):
        if whence == 0:
            self.needle = offset
        elif whence == 1:
            self.needle += offset
        else:
            self.needle = self.file_size + offset

    def tell(self):
        return self.needle

    def read(self, size=-1):
        # Determine what block the needle is in
        block, offset = divmod(self.needle, 64)
        self.fp.seek(block*64+72, 0)
        data = bytearray(self.fp.read(-1 if size == -1 else size+offset))
        if len(data) > 0:
            self.crypter.chacha_encrypt(data, self.nonce, block+1)
            data[:] = data[offset:]
        if self.file_mode == 'r':
            return codecs.decode(data, encoding=self.encoding)
        else:
            self.needle += len(data)
            return data

    def unpack(self, f, chunk_size=2**29):  # Unpacks the archive
        self.seek(0)
        while True:
            chunk = self.read(chunk_size)
            if not chunk:
                break
            f.write(chunk)

