"""
Nescient Encryption Suite 0.3.1

nescient, n. -- from Latin 'unknowing'
A program for packing and unpacking encrypted, salted, and authenticated single-file containers

Script for running from the command line
"""
import argparse  # Parse arguments passed to the script
import getpass # For getting passwords without terminal echo
import glob  # For expanding path wildcards

from nescient.packer import *

def main():
    """ Argument parser, for use from the command line """
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     prog='nescient',
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
            password = getpass.getpass('Please specify password: ')
            if args.n is False:
                password2 = getpass.getpass('Please verify password:  ')
            else: password2 = password
            if password != password2:
                print('Passwords do not match!')
                quit()
            else:
                print('Got password from input')
        except KeyboardInterrupt:
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
