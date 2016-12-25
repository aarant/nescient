#!/user/bin/env python3
from distutils.core import setup
from distutils.extension import Extension

setup(name='Nescient',
      version='0.2.0',
      description='Encrypt and decrypt single files to/from secure containers',
      long_description='Python program for (un)packing encrypted, salted, and authenticated single-file containers',
      author='Andrew Antonitis',
      author_email='andrewan@mit.edu',
      packages=['nescient', 'nescient.aes'],
      ext_modules=[Extension('nescient.aes.aes', ['nescient/aes/aes.c'])],
      scripts=['bin/nescient'],
      license='MIT'
      )
