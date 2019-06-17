# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Ariel Antonitis. Licensed under the MIT license.
#
# setup.py
import sys
from setuptools import setup
from setuptools.extension import Extension

from nescient import __version__, url

with open('README.rst', 'r') as f:
    long_description = f.read()

# Compiler arguments are different for Windows and Linux,
# try to use OpenMP on both
if sys.platform.startswith('win32'):
    extra_compile_args = ['/openmp', '/Ox']
    extra_link_args = ['/openmp', '/Ox']
else:
    extra_compile_args = ['-fopenmp', '-O3']
    extra_link_args = ['-fopenmp', '-O3']

USE_CYTHON = False
ext = 'pyx' if USE_CYTHON else 'c'
extensions = [Extension('nescient.crypto.aes', ['nescient/crypto/aes.%s' % ext]),
              Extension('nescient.crypto.chacha', ['nescient/crypto/chacha.%s' % ext],
                        extra_compile_args=extra_compile_args, extra_link_args=extra_link_args)]
if USE_CYTHON:
    from Cython.Build import cythonize
    extensions = cythonize(extensions)

setup(name='Nescient',
      version=__version__,
      description='Store, encrypt and decrypt files to and from encrypted, authenticated containers.',
      long_description=long_description,
      author='Ariel Antonitis',
      author_email='arant@mit.edu',
      url=url,
      packages=['nescient', 'nescient.crypto', 'nescient.resources', 'nescient.gui'],
      package_data={'nescient': ['*.png', '*.ico'], 'nescient.crypto': ['*.pyx', '*.pxd'],
                    'nescient.resources': ['*gif']},
      ext_modules=extensions,
      entry_points={'console_scripts': ['nescient = nescient.__main__:main'],
                    'gui_scripts': ['nescient-ui = nescient.__main__:start_gui']},
      license='MIT',
      classifiers=['License :: OSI Approved :: MIT License',
                   'Development Status :: 4 - Beta',
                   'Topic :: Security :: Cryptography',
                   'Programming Language :: Python :: 3.5',
                   'Programming Language :: Python :: 3.6'],
      install_requires=['pillow>=6.0.0,<7.0.0'],
      python_requires='>=3.5'
      )
