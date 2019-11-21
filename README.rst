.. |pypi| image:: https://img.shields.io/pypi/v/nescient.svg
.. _pypi: https://pypi.python.org/pypi/Nescient
.. |license| image:: https://img.shields.io/github/license/arantonitis/nescient.svg
.. _license: https://github.com/arantonitis/nescient/tree/master/LICENSE
.. |travis| image:: https://travis-ci.org/arantonitis/nescient.svg?branch=master
.. _travis: https://travis-ci.org/arantonitis/nescient/
.. |appveyor| image:: https://ci.appveyor.com/api/projects/status/r5p0hg36srwi2k06?svg=true
.. _appveyor: https://ci.appveyor.com/project/arantonitis/nescient
.. |nessie| image:: https://raw.githubusercontent.com/arantonitis/nescient/master/nescient/nessie.png
   :height: 64px
   :width: 64px
   :align: middle
   :alt:

|nessie| Nescient
*****************
|pypi|_ |license|_ |travis|_ |appveyor|_

*nescient, n. (nesh-int) - from Latin 'unknowing', 'hidden'*

Store, encrypt and decrypt files to and from encrypted, authenticated containers.

Nescient provides an easy-to-use, secure, and efficient means of file or memory level encryption.

Several use cases include:

* Backing up multiple files to a reliable yet insecure location.

* Providing additional, file-level encryption to supplement full disk encryption, securing packed files even while the machine is on with the disk-level encryption key loaded in memory.

* Sharing files with others securely, by transferring a Nescient container through an insecure channel and providing a password through a separate secure channel.

* Using Nescient's cryptographic classes to efficiently implement secure protocols.

Nescient is:

* **open source**: Licensed under the permissive MIT license.

* **multiplatform**: As a Python project, Nescient works on all the major operating systems (Windows, macOS, and Linux)

* **transparent**: The means with which Nescient encrypts and packs files is documented, and the algorithms used are tested both against official test vectors and arbitrary data to ensure correctness.

* **fast**: All core crypto code is written in Cython and compiled to C extensions, making it fast enough to be practically usable for large files. The fastest cipher modes achieve speeds of 10 cycles/byte.

Nescient supports the following packing modes:

* The AES block cipher for encryption, with either 128, 192, or 256 bit keys, in CBC mode, and SHA-256 for generating authentication tags.

* The ChaCha20 stream cipher with 256 bit keys and SHA-256 for generating authentication tags.

Installation
============

Windows
-------
Nescient is available as a pre-packaged, standalone Windows executable, downloadable from the `github releases`_. The executable can be used in GUI-mode, by double-clicking, or can be run with command line arguments.

From PyPI
---------
Nescient requires Python 3.4 or later.

Windows users installing Nescient as a Python package are **strongly suggested** to have a 64-bit Python installation on their machines. Otherwise, installation may require installing the Microsoft C++ Visual Build Tools to compile Nescient's C extensions.

Install Nescient from the Python Package Index (PyPI) by running ``pip install nescient``.

.. note::

   * On most Linux systems, installation may require running pip with root permissions, or running ``pip install nescient --user`` instead.

   * On most Linux systems, there may be two versions of pip available: The Python 3 version is typically called ``pip3``.

From Releases
-------------
An arbitrary stable (not development) release can be installed from the `github releases`_ by downloading the zip archive and running ``pip install <path-to-zip``.

From latest source
------------------
Clone or download the `git repo`_, navigate to the directory, then run::

   python3 setup.py sdist
   cd dist
   pip install Nescient-<version>.tar.gz

Installing from source may require installing compilation tools.

.. _github releases: https://github.com/arantonitis/nescient/releases
.. _git repo: https://github.com/arantonitis/nescient

Usage
=====
Nescient has a GUI mode, which can be run by simply running ``nescient-ui``, or ``nescient`` with no arguments.

Nescient can pack or unpack files into/from ``.nesc`` containers. Some typical usage might be:

``nescient pack file1 file2``

``nescient unpack file1.nesc``

Unless otherwise specified via command line flags, Nescient packs and unpacks files in place, overwriting their data.

Command line help can be viewed with ``nescient -h``.

Development
===========
Nescient versioning functions on a ``MAJOR.MINOR.PATCH.[DEVELOP]`` model. Only stable, non development releases will be published to PyPI. Because Nescient is still a beta project, the ``MAJOR`` increment will be 0. Minor increments represent new features. Patch increments represent problems fixed with existing features.

Planned features include:

* New cipher modes for existing algorithms, like the GCM authenticated mode, and additional encryption algorithms.

* Integrated compression when packing files.

* GUI mode enhancements.

* Documentation.
