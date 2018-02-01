# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Ariel Antonitis. Licensed under the MIT license.
#
# nescient/timing.py
""" Classes and functions to read/write timing benchmarks, and estimate the time needed to pack/unpack a file. """
# TODO: Documentation, better timer
import os
import sys
import pickle
from time import sleep
from threading import Thread
from timeit import default_timer as timer
from pkg_resources import Requirement, resource_filename

from nescient.packer import NescientPacker
from nescient.crypto.tools import get_random_bytes


# The path to the pickled benchmark file
BENCHMARK_PATH = os.path.join(os.path.expanduser('~'), 'nescient-benchmarks')
#BENCHMARK_PATH = resource_filename(Requirement.parse('Nescient'), os.path.join('nescient', 'benchmark'))


def load_benchmarks():
    try:
        with open(BENCHMARK_PATH, 'rb') as f_in:
            benchmarks = pickle.load(f_in)
            return benchmarks
    except Exception:
        return {}


def write_benchmarks(mode, times):
    benchmarks = load_benchmarks()
    benchmarks[mode] = times
    with open(BENCHMARK_PATH, 'wb') as f_out:
        pickle.dump(benchmarks, f_out)


def estimate_time(size, packing_mode):
    benchmarks = load_benchmarks()
    if benchmarks is None or benchmarks.get(packing_mode) is None:
        return None
    times = benchmarks[packing_mode]
    # Find the benchmarked size that is closest to the requested size
    diff = [(abs(size-benchmarked_size), benchmarked_size) for benchmarked_size in times]
    _, closest = min(diff, key=lambda t: t[0])
    # Compute an estimated time
    estimated = size/closest*times[closest][-1]
    min_time = min(times.values(), key=lambda l: l[-1])[-1]
    # It is extremely unlikely that the estimated time can be less than the minimum benchmarked time, so take the max
    return max(estimated, min_time)

def benchmark_mode(packing_mode):
    alg, mode, auth = packing_mode.split('-', 2)
    packer = NescientPacker(get_random_bytes(16), alg, mode, auth)
    times = {}
    for size in [2**x for x in range(10, 35, 5)]:
        times[size] = []
        data = bytearray(size)
        # Calculate key generation rate
        start = timer()
        checkpoint = timer()
        salt = get_random_bytes(16)
        key = packer._key_gen(salt)
        times[size].append(timer() - checkpoint)
        # Calculate encryption rate
        checkpoint = timer()
        packer._encrypt(data, key, salt)
        times[size].append(timer() - checkpoint)
        # Calculate authentication rate
        checkpoint = timer()
        packer._gen_auth_tag(key, bytearray(24) + salt, data)
        times[size].append(timer() - checkpoint)
        # Calculate total rate
        times[size].append(timer() - start)
    write_benchmarks(packing_mode, times)


class EstimatedProgressBar:
    def __init__(self, size, rate, n_chunks=64):
        self.size, self.rate, self.n_chunks = size, rate, n_chunks
        self.finished = False
        self.start_time = None
        self.elapsed = 0
        self.est_time = float(size) / float(rate)
        self.interval = self.est_time / self.n_chunks

    def run_progress(self):
        self.start_time = timer()
        self.elapsed = 0
        while not self.finished:
            self.display()
            sleep(self.interval)
            self.elapsed = timer() - self.start_time
        self.finished = True
        self.display()

    def display(self):
        if self.finished or self.elapsed >= self.est_time:
            chunks = self.n_chunks
        else:
            chunks = int(self.elapsed / self.interval)
        display_string = '\r[' + '='*chunks + ' '*(self.n_chunks-chunks) + '] ' + str(self.rate) + 'Mb/s '
        if self.finished:
            display_string += 'Completed!'
        elif self.elapsed >= self.est_time:
            display_string += '?'
        else:
            remaining = int(self.est_time - self.elapsed)
            m, s = divmod(remaining, 60)
            h, m = divmod(m, 60)
            display_string += '%02d:%02d:%02d' % (h, m, s)
        print(display_string, end='\r')

    def start(self):
        t = Thread(target=self.run_progress, daemon=True)
        t.start()

    def stop(self):
        self.finished = True


class EstimatedTimer:
    def __init__(self, text, est_time, display_func=None):
        self.text, self.est_time, self.display_func = text, est_time, display_func
        if len(self.text) > 66:  # TODO: Terminal width
            self.text = self.text[:59] + '(cont.)'
        self.error, self.finished = False, False
        self.frame = 0
        self.frames = ['|', '/', '-', '\\']

    def run_progress(self):
        self.start_time = timer()
        self.elapsed = 0
        while not self.finished:
            self.display()
            sleep(0.5)
            self.frame = (self.frame + 1) % 4
            self.elapsed = timer() - self.start_time
        self.finished = True

    def display(self):
        display_string = self.text + '...'
        if self.error:
            display_string += 'ERROR     '
        elif self.finished:
            display_string += 'Completed!'
        #display_string += '(' + str(self.size) + ' Mb, ' + str(self.rate) + ' Mb/s) '
        elif self.est_time is None:
            display_string += 'Unknown ' + self.frames[self.frame]
        elif self.elapsed > self.est_time:
            display_string += 'Overtime ' + self.frames[self.frame]
        else:
            remaining = int(self.est_time - self.elapsed)
            m, s = divmod(remaining, 60)
            h, m = divmod(m, 60)
            display_string += '%02d:%02d:%02d ' % (h, m, s) + self.frames[self.frame]
        if self.display_func:
            self.display_func(display_string)
        else:
            print('\r' + display_string, end='' if not self.finished else '\n', flush=True)

    def start(self):
        t = Thread(target=self.run_progress, daemon=True)
        t.start()

    def stop(self, error=False):
        self.error = error
        self.finished = True
        self.display()


class TkTimer(EstimatedTimer):
    def __init__(self, root, text, est_time, display_func):
        EstimatedTimer.__init__(self, text, est_time, display_func)
        self.root = root

    def run_progress(self):
        if not self.finished:
            self.display()
            self.frame = (self.frame + 1) % 4
            self.elapsed = timer() - self.start_time
            self.root.after(500, self.run_progress)

    def start(self):
        self.start_time = timer()
        self.elapsed = 0
        self.run_progress()
        
        
