# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Ariel Antonitis. Licensed under the MIT license.
#
# nescient/process.py
""" Functions for starting a new process to pack files. """
import sys
from multiprocessing import Process, Queue

from nescient.packer import NescientPacker


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
