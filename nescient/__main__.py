# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT license.
#
# nescient/__main__.py
""" Allows use of Nescient from the command line. """
# TODO: Document STDIN functionality, make ArgumentParsers hierarchical
import os
import sys
import glob
from getpass import getpass
from multiprocessing import Process, Queue
from argparse import ArgumentParser, RawTextHelpFormatter

from nescient import __version__, __doc__ as description
from nescient.packer import SUPPORTED_ALGS, NescientPacker
from nescient.timing import estimate_time, EstimatedTimer


# Prompt the user with a yes-no question
def ask_yesno(prompt, default=True, newline=False, noprompt=False):
    if noprompt:
        print(prompt + ' Y' if default else prompt + ' N')
        if newline:
            print()
        return default
    if default:
        result = input(prompt + ' (Y/n): ')
        if newline:
            print()
        return result not in ['N', 'n']
    else:
        result = input(prompt + ' (y/N): ')
        if newline:
            print()
        return result in ['Y', 'y']


# Fetch all the available packing modes
def get_packing_modes():
    choices = []
    for alg, (CrypterClass, _) in SUPPORTED_ALGS.items():
        for mode in CrypterClass.modes:
            for auth in CrypterClass.auth:
                choices.append(alg + '-' + mode + '-' + auth)
    return choices


def target_func(queue, settings, in_path, out_path, packing_choice, overwrite=True):
    password, alg, mode, auth = settings
    try:
        packer = NescientPacker(password, alg, mode, auth)
        packer.pack_or_unpack_file(in_path, out_path, packing_choice, overwrite)
    except Exception as e:
        queue.put(e)
        sys.exit(1)


# Start a packing process to run alongside the main one
def start_packer_process(packer, in_path, out_path, packing_choice, overwrite=True):
    queue = Queue()
    p = Process(target=target_func, daemon=True, args=(queue, (packer.password, packer.alg, packer.mode, packer.auth),
                                                       in_path, out_path, packing_choice, overwrite))
    p.start()
    return p, queue


# Main program entrypoint
def main():
    parser = ArgumentParser(prog='nescient', description=description, formatter_class=RawTextHelpFormatter)
    parser.add_argument('packing_choice', choices=['pack', 'unpack'], metavar='pack|unpack',
                        help='Whether to pack or unpack the specified files.')
    parser.add_argument('patterns', nargs='+', help='File paths or patterns to process. Accepts wildcards like * or ?.',
                        type=str, metavar='paths')
    parser.add_argument('-o', dest='out_path', metavar='output path',
                        help='The path to write the processed files to.\n'
                             'By default, files are processed and written to their containing directory.\n'
                             'If a directory, each file will be processed as if it were in that directory.\n'
                             'Must be a directory if multiple files are specified.\n'
                             'If only one file is specified, this argument may be a filename, in which case\n'
                             'the processed file will be written directly to that path.')
    parser.add_argument('-m', choices=get_packing_modes(), default='chacha-stm-sha', dest='mode',
                        help='The algorithm, cipher mode, and authentication mode to use when packing.')
    parser.add_argument('-nr', '-norecursive', dest='recursive', action='store_false', default=True,
                        help='If wildcards are used as input paths, prevents recursively checking subdirectories.')
    parser.add_argument('-np', '-noprompt', dest='noprompt', action='store_true', default=False,
                        help='Prevent Nescient from prompting the user and forces the use of default options.')
    parser.add_argument('-nd', '-nodelete', dest='overwrite', action='store_false', default=True,
                        help='Prevent Nescient from overwriting the original file during processing.')
    args = parser.parse_args()
    noprompt, overwrite, recursive = args.noprompt, args.overwrite, args.recursive
    # Retrieve packer mode information
    alg, mode, auth = args.mode.split('-', 2)
    packing_choice, patterns, out_path = args.packing_choice, args.patterns, args.out_path
    # Build paths and ensure they are valid
    paths = [path for pattern in patterns for path in glob.glob(pattern, recursive=recursive) if os.path.isfile(path)]
    if len(paths) == 0:
        print('No file(s) found with the path(s) specified.')
        sys.exit(1)
    if len(paths) > 1 and out_path is not None and not os.path.isdir(out_path):
        print('Output path must be a directory when specifying multiple input files.')
        sys.exit(1)
    # Create Nescient header
    print('== Nescient v' + __version__ + ' ==\n')
    print('Packing mode:', args.mode + '\n')
    # Prompt for password
    if sys.stdin.isatty():  # If reading from a terminal, prompt for the password
        password = getpass('Insert password: ')
        password2 = getpass('Verify password: ')
        if password != password2:
            print('\nPasswords do not match!')
            sys.exit(1)
        print()
    else:  # Otherwise read from STDIN and do not prompt
        password = input('')
        noprompt = True
    # Build the packer, and if packing, check for benchmarks
    packer = NescientPacker(password, alg, mode, auth)
    if packing_choice == 'pack' and packer.times is None:  # Ask to generate benchmarks if there are none
        if ask_yesno('No current benchmarks for these settings. Generate some?', noprompt=noprompt):
            print('Generating benchmarks...')
            packer.benchmark()
            print()
    prompt_each = ask_yesno('Confirm each file?', default=False, newline=True, noprompt=noprompt)
    print('Packing:' if packing_choice == 'pack' else 'Unpacking:')
    for file_path in paths:
        file_out_path = NescientPacker.fix_out_path(file_path, out_path, packing_choice)
        display_text = file_path + ' > ' + file_out_path
        print(display_text, end='')
        if prompt_each:
            process_file = ask_yesno('')
            if not process_file:
                continue
        display_text = os.path.split(file_path)[1] + ' > ' + os.path.split(file_out_path)[1]
        est_time = None if packer.times is None else estimate_time(os.path.getsize(file_path), packer.times)
        timer = EstimatedTimer(display_text, est_time)
        p, queue = start_packer_process(packer, file_path, file_out_path, packing_choice, overwrite=overwrite)
        timer.start()
        p.join()
        if queue.empty():
            timer.stop()
        else:
            e = queue.get()
            timer.stop(error=True)
            print(e.__class__.__name__ + ':', e)


if __name__ == '__main__':
    main()
