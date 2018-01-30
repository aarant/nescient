# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT License.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# nescient/__init__.py
"""Nescient v0.5.0

A Python program for packing/unpacking encrypted, salted, and authenticated file containers.

Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT License.
"""
from string import digits

# Versions will always take the form major.minor.patch[.develop]. The develop increment is optional.
# A valid version will have the string form *.*.*[.dev*], where any integer may take the place of a *.
__version__ = '0.5.0'


def version_to_tuple(version):
    """ Convert a version string to a `(major, minor, patch, develop)` tuple.

    Args:
        version (str): The version string to convert, in the form '*.*.*.dev*'.

    Returns:
        tuple: The version in the form of a `(major, minor, patch, develop)` tuple.
    """
    strings = version.split('.', 3)
    incs = [int(''.join([c for c in s if c in digits]))for s in strings]
    if len(incs) == 3:
        incs.append(float('inf'))  # Lack of a development version is treated as an infinite value
    return tuple(incs)


def newer_version(version_1, version_2):
    """ Determine which of two version strings is newer.

    Args:
        version_1 (str): The first version to compare.
        version_2 (str): The second.

    Returns:
        int: 1 if the first version is newer, 2 if the second is, and 0 if they are equal.
    """
    incs_1 = version_to_tuple(version_1)
    incs_2 = version_to_tuple(version_2)
    for inc_1, inc_2 in zip(incs_1, incs_2):
        if inc_1 > inc_2:
            return 1
        elif inc_2 > inc_1:
            return 2
    return 0


class NescientError(Exception):
    """ Base Nescient error from which all others inherit. """
    pass
