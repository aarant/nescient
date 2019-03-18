#!/usr/bin/python3
import sys
import subprocess

from nescient import __version__
from PyInstaller.__main__ import run

args = ['--clean', '-y', '-w', '-F', '--distpath', 'pyinst-dist', '--workpath', 'pyinst-build', '--specpath', 'pyinst-build',
        '--hidden-import', 'nescient.crypto.galois', '--hidden-import', 'PyQt5.sip', '-i', 'nescient/nessie.ico', '-n',
        'Nescient-%s' % __version__, 'nescient/__main__.py']

run(args)
