# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Ariel Antonitis. Licensed under the MIT license.
#
# nescient/__main__.py
""" Allows use of Nescient from the command line. """
# TODO: Document STDIN functionality, make ArgumentParsers hierarchical
import os
import sys
import glob
from getpass import getpass
from argparse import ArgumentParser, RawTextHelpFormatter

from nescient import __version__, __doc__ as description
from nescient.packer import PACKING_MODES, DEFAULT_PACKING_MODE, NescientPacker, PackingError
from nescient.timing import estimate_time, EstimatedTimer, load_benchmarks, benchmark_mode
from nescient.process import start_packer_process
from nescient.gui import NescientUI


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


# Main program entrypoint
def main():
    # If run with no arguments, start the GUI
    if len(sys.argv) == 1:
        gui = NescientUI()
        gui.mainloop()
        sys.exit(0)
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
    parser.add_argument('-m', choices=PACKING_MODES, default=DEFAULT_PACKING_MODE, dest='mode',
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
    # Build the packer, and check for benchmarks
    packer = NescientPacker(password, alg, mode, auth)
    benchmarks = load_benchmarks()
    if benchmarks is None or benchmarks.get(args.mode) is None:  # Ask to generate benchmarks if there are none
        if ask_yesno('No current benchmarks for these settings. Generate some?', noprompt=noprompt):
            print('Generating benchmarks...')
            benchmark_mode(args.mode)
            print()
    prompt_each = ask_yesno('Confirm each file?', default=False, newline=True, noprompt=noprompt)
    print('Packing:' if packing_choice == 'pack' else 'Unpacking:')
    for file_path in paths:
        try:
            # Fix the out path and set up display text
            file_out_path = NescientPacker.fix_out_path(file_path, out_path, packing_choice)
            display_text = file_path + ' > ' + file_out_path
            print(display_text, end='')
            if prompt_each:
                process_file = ask_yesno('')
                if not process_file:
                    continue
            display_text = os.path.split(file_path)[1] + ' > ' + os.path.split(file_out_path)[1]
            # Determine estimated time
            if packing_choice == 'pack':
                packing_mode = packer.alg + '-' + packer.mode + '-' + packer.auth
            else:
                parsed = NescientPacker.parse_nescient_header(file_path)
                packing_mode = parsed['alg'] + '-' + parsed['mode'] + '-' + parsed['auth']
            est_time = estimate_time(os.path.getsize(file_path), packing_mode)
            # Set up the timer and packing process
            timer = EstimatedTimer(display_text, est_time)
            p, queue = start_packer_process(packer, file_path, file_out_path, packing_choice, overwrite=overwrite)
            timer.start()
            p.join()
            if queue.empty():
                timer.stop()
            else:
                timer.stop(error=True)
                e = queue.get()
                print(e.__class__.__name__ + ':', e)
        except PackingError as e:
            print(e.__class__.__name__ + ':', e)


if __name__ == '__main__':
    main()
