# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Ariel Antonitis. Licensed under the MIT license.
#
# nescient/process.py
""" Functions for executing functions in a new process, synchronously. """
import sys
from multiprocessing import Process, Queue


def _target_func(func, queue, *args, **kwargs):
    try:
        rtn = func(*args, **kwargs)
    except Exception as e:
        queue.put(e)
        sys.exit(1)
    else:
        queue.put(rtn)
        sys.exit(0)


def process_sync_execute(func, *args, **kwargs):
    queue = Queue()
    p = Process(target=_target_func, args=(func, queue) + args, kwargs=kwargs)
    p.start()
    p.join()
    if queue.empty():
        raise Exception('Process exited improperly or prematurely.')
    rtn = queue.get()
    if isinstance(rtn, Exception):
        raise rtn
    return rtn


def process_sync_wrapper(func):
    def wrapped_func(*args, **kwargs):
        return process_sync_execute(func, *args, **kwargs)
    return wrapped_func
