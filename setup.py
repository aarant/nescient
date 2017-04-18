#!/user/bin/env python3
import ez_setup
ez_setup.use_setuptools()
from setuptools import setup
from setuptools.extension import Extension

setup(name='Nescient',
      version='0.3.1',
      description='Encrypt and decrypt single files to/from secure containers',
      long_description='Python program for (un)packing encrypted, salted, and authenticated single-file containers',
      author='Andrew Antonitis',
      author_email='andrewan@mit.edu',
      packages=['nescient', 'nescient.crypto'],
      ext_modules=[Extension('nescient.crypto.aes', ['nescient/crypto/aes.c'])],
      entry_points={'console_scripts':['nescient=nescient.__main__:main']},
      license='MIT'
      )
