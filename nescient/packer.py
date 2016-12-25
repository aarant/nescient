"""
Nescient Encryption Suite 0.3

nescient, n. -- from Latin 'unknowing'
A program for packing and unpacking encrypted, salted, and authenticated single-file containers
"""
import os
import hmac  # Generating authentication tags with SHA-2
from hashlib import pbkdf2_hmac  # PBKDF2 Key derivation

# Algorithm imports
from .aes import aes  # AES

class NescientError(Exception):
    """ Generic Nescient error """
    def __init__(self, message):
        self.message = message

class ParamError(NescientError):
    """ Signifies that invalid parameters were specified """
    pass

class AuthError(NescientError):
    """ Signifies that the data was not authenticated properly """
    pass

class UnpackingError(NescientError):
    """ Signifies that there was an error in unpacking -- usually because the file is invalid """
    pass

class NescientPacker:
    """
    Nescient Packer/Unpacker Class

    Initialized with a password and parameters for preferred mode of operation
    Can pack a file into an .nesc container
    Can also unpack arbitrary .nesc containers (so long as their headers are valid)
    """

    def __init__(self, password, alg='aes256', mode='cbc', auth='sha'):
        # password must be a bytes object in order to work with the key generation,
        # so if it's a string, we convert it
        if type(password) is str:
            self.password = bytes(password, 'utf-8')
        elif type(password) is bytes:
            self.password = password
        else:
            raise ParamError('Password is not of proper type (string or bytes)')
        # Supported algorithms and modes. Right now only AES-256-CBC is supported
        if alg == 'aes256' and mode == 'cbc':
            self.keyLen = 256 / 8  # key length is 32 bytes or 256 bits
            self.algCrypter = aes.AesCrypter
        else:
            raise ParamError('Invalid cipher mode specified')
        self.alg = alg
        self.mode = mode
        # Supported authenticated encryption protocols. TODO: Only SHA-256 is supported right now
        if auth == 'sha':
            self.authTag = lambda key, authData, encData: hmac.new(key, authData + encData, digestmod='sha256').digest()
        else:
            raise ParamError('Invalid auth mode specified')
        self.auth = auth

    # Performs PBKDF2 key derivation with a specified salt
    def keyGen(self, salt):
        return pbkdf2_hmac('sha256', self.password, salt, 100000, self.keyLen)

    # Encrypts an arbitrary block of data, adding and returning the decrypted data and the salt used
    def encrypt(self, data):
        salt = os.urandom(16)  # TODO: try and do this more securely?
        key = self.keyGen(salt)
        algCrypter = self.algCrypter(key, self.mode)
        return algCrypter.encrypt(data), salt

    # Decrypts data, performing key generation with a specified salt
    def decrypt(self, data, salt):
        key = self.keyGen(salt)
        algCrypter = self.algCrypter(key, self.mode)  # Initialize the crypter object
        return algCrypter.decrypt(data)

    def pack(self, inPath, outPath):
        """ Pack a file with the packer settings, saving it as a new file """
        with open(inPath, 'rb') as fIn:
            # Generate 16 byte Nescient header data
            header = bytearray('NESC' + self.alg + self.mode + self.auth, 'utf-8')
            # Open the file and read in data
            fSize = os.path.getsize(inPath)
            data = bytearray(fSize)
            fIn.readinto(data)
            # Encrypt the data and retrieve the random salt used
            data, salt = self.encrypt(data)
            # Generate an authentication tag
            key = self.keyGen(salt)
            authTag = self.authTag(key, header + salt, data)
            # Write header, salt, authentication tag, and encrypted data to file
            with open(outPath, 'wb') as fOut:
                fOut.write(header)
                fOut.write(salt)
                fOut.write(authTag)
                fOut.write(data)
        return

    def unpack(self, inPath, outPath):
        """ Unpack a file using the settings specified by its (valid) header """
        with open(inPath, 'rb') as fIn:
            # Open the file and read in header data
            fSize = os.path.getsize(inPath)
            header = fIn.read(16)
            if header[0:4] != b'NESC':  # Check for magic bytes
                raise UnpackingError('Not a valid NESC file')
            alg = header[4:10].decode('utf-8')
            mode = header[10:13].decode('utf-8')
            auth = header[13:16].decode('utf-8')
            # Try to initialize a temporary unpacker with file settings
            try:
                tempUnpacker = self.__class__(self.password, alg, mode, auth)
            except ParamError as e:  # Header in valid
                raise UnpackingError(e.message + ' in file')
            # Get the salt from the file and generate keys accordingly
            salt = fIn.read(16)
            # Check integrity of message using authentication tag
            if auth == 'sha':
                authTag = fIn.read(32)
                data = bytearray(fSize - 64)  # 16 header bytes, 16 salt bytes, and 32 authTag bytes = 64
                fIn.readinto(data)
                key = tempUnpacker.keyGen(salt)
                newAuthTag = tempUnpacker.authTag(key, header + salt, data)
                if hmac.compare_digest(authTag, newAuthTag) is not True:
                    raise AuthError('!!Authentication tag values not equal!!')
            else:  # FOO; Otherwise fuck it, don't even check integrity :)
                data = bytearray(fSize - 32)  # 16 header bytes + 16 salt bytes
                fIn.readinto(data)
            # Decrypt data with the specified cipher mode and salt
            data = tempUnpacker.decrypt(data, salt)
            # Write decrypted data to file
            with open(outPath, 'wb') as fOut:
                fOut.write(data)
        return

if __name__ == '__main__':
    """ Argument parser, for use from the command line """
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='Nescient Encryption Suite 0.3\n'
                                                 'A program for packing and unpacking '
                                                 'encrypted, salted, and authenticated single file containers', prefix_chars='-+')
    parser.add_argument('patterns', metavar='file', nargs='+', type=str, help='A file (pattern) to be packed/unpacked')
    parser.add_argument('-m', type=str, help='Packing method',
                        default='aes256-cbc-sha256', choices=['aes256-cbc-sha256'])
    parser.add_argument('-n', action='store_true', help='Do not verify password')
    parser.add_argument('-kf', metavar='keyfile', type=str, help='Optional keyfile')
    parser.add_argument('-o', metavar='outputDir', type=str, help='Output directory')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', action='store_true', help='pack')
    group.add_argument('-u', '+u', action='store_true', help='unpack')
    args = parser.parse_args()
    

    # If using normal password input
    if args.kf is None:
        try:
            stdscr = curses.initscr()
            curses.noecho()
            stdscr.addstr('Please specify password: ')
            password = stdscr.getstr().decode('utf-8')
            if args.n is False:
                stdscr.addstr('Please verify password:  ')
                password2 = stdscr.getstr().decode('utf-8')
            else: password2 = password
            curses.echo()
            curses.endwin()
            if password != password2:
                print('Passwords do not match!')
                quit()
            else:
                print('Got password from input')
        except KeyboardInterrupt:
            curses.echo()
            curses.endwin()
            quit()
    # If using a keyfile
    else:
        with open(args.kf, 'r') as f:
            password = f.read()
            if password[-1] == '\n': password = password[:-1]
        print('Got password from keyfile')
    # Set crypter parameters and attempt to initialize it
    if args.m == 'aes256-cbc-sha256':
        alg = 'aes256'
        mode = 'cbc'
        auth = 'sha'
    try:
        packer = NescientPacker(password, alg, mode, auth)
    except ParamError as e:
        print(e.message)
        quit()
    print('Using method ' + args.m)
    for pattern in args.patterns:
        paths = glob.glob(pattern)
        for inPath in paths:
            if os.path.isfile(inPath):
                # Pack file
                if args.p:
                    if args.o:
                        outPath = os.path.join(args.o, os.path.basename(inPath) + '.nesc')
                    else:
                        outPath = inPath + '.nesc'
                    print('Packing file ' + inPath + '...')
                    try:
                        packer.pack(inPath, outPath)
                        print('Packed to ' + outPath)
                    except FileNotFoundError:
                        print('File not found')
                        quit()
                # Unpack file
                else:
                    if args.o:
                        outPath = os.path.join(args.o, os.path.splitext(inPath)[0])
                    else:
                        outPath = os.path.splitext(inPath)[0]
                    print('Unpacking file ' + inPath + ' (using file specs)...')
                    try:
                        packer.unpack(inPath, outPath)
                        print('Unpacked to ' + outPath)
                    except UnpackingError as e:
                        print(e.message)
                        quit()
                    except AuthError as e:
                        print(e.message + '\nEither this file has been tampered with, or you entered the key wrong')
                        quit()
    quit()
