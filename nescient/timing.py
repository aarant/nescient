# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT license.
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


def estimate_time(size, times):
    # Find the benchmarked size that is closest to the requested size
    diff = [(abs(size-benchmarked_size), benchmarked_size) for benchmarked_size in times]
    _, closest = min(diff, key=lambda t: t[0])
    # Compute an estimated time
    estimated = size/closest*times[closest][-1]
    min_time = min(times.values(), key=lambda l: l[-1])[-1]
    # It is extremely unlikely that the estimated time can be less than the minimum benchmarked time, so take the max
    return max(estimated, min_time)


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
    def __init__(self, text, est_time):
        self.text, self.est_time = text, est_time
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
        print('\r' + display_string, end='' if not self.finished else '\n', flush=True)

    def start(self):
        t = Thread(target=self.run_progress, daemon=True)
        t.start()

    def stop(self, error=False):
        self.error = error
        self.finished = True
        self.display()
