# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Andrew Antonitis. Licensed under the MIT license.
#
# setup.py
from setuptools import setup
from setuptools.extension import Extension

from nescient import __version__

with open('README.rst', 'r') as f:
    long_description = f.read()

USE_CYTHON = False
if USE_CYTHON:
    from Cython.Build import cythonize
    extensions = cythonize([Extension('nescient.crypto.aes', ['nescient/crypto/aes.pyx']),
                            Extension('nescient.crypto.chacha', ['nescient/crypto/chacha.pyx'])])
else:
    extensions = [Extension('nescient.crypto.aes', ['nescient/crypto/aes.c']),
                  Extension('nescient.crypto.chacha', ['nescient/crypto/chacha.c'])]

setup(name='Nescient',
      version=__version__,
      description='A Python program for packing/unpacking encrypted, salted, and authenticated file containers.',
      long_description=long_description,
      author='Andrew Antonitis',
      author_email='arant@mit.edu',
      url='https://github.com/arantonitis/nescient',
      packages=['nescient', 'nescient.crypto'],
      package_data={'nescient': ['*.png'], 'nescient.crypto': ['*.pyx']},
      ext_modules=extensions,
      entry_points={'console_scripts': ['nescient = nescient.__main__:main']},
      license='MIT',
      classifiers=['License :: OSI Approved :: MIT License'],
      python_requires='>=3.3'
      )
