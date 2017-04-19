#!/user/bin/env python3
from setuptools import setup
from setuptools.extension import Extension

setup(name='Nescient',
      version='0.3.2',
      description='Pack/unpack files to/from encrypted containers',
      long_description='Python program for packing/unpacking encrypted, salted, and authenticated single file containers',
      author='Andrew Antonitis',
      author_email='andrewan@mit.edu',
      url='https://github.com/aantonitis/nescient',
      packages=['nescient', 'nescient.crypto'],
      package_data={'': ['*.pyx'],},
      ext_modules=[Extension('nescient.crypto.aes', ['nescient/crypto/aes.c'])],
      entry_points={'console_scripts':['nescient=nescient.app:main']},
      license='MIT',
      )
