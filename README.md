[pypi]: <https://pypi.org/project/Nescient/>
[license]: <https://github.com/arantonitis/nescient/tree/master/LICENSE>

# ![nessie](https://raw.githubusercontent.com/arantonitis/nescient/master/nescient/nessie.png) Nescient
[![PyPI badge](https://img.shields.io/pypi/v/nescient.svg)][pypi]
[![License badge](https://img.shields.io/github/license/arantonitis/nescient.svg)][license]

*nescient, n. (nesh-int) - from Latin 'unknown', 'hidden'*

Pack files to and from encrypted, authenticated containers.

Nescient provides an easy-to-use, secure, and efficient means of file or memory level encryption.

Use cases include:

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

## Installation
### Windows
Standalone Windows executables can be downloaded from the [releases](https://github.com/arantonitis/nescient/releases). They can be used in GUI-mode or accept command-line arguments.

### From PyPI
Nescient requires Python 3.5 or later.

Run `<python> -m pip install nescient`, where `<python>` is your Python executable, typically `python`, `python3`, or `py`.

> **Windows:** If installing on a 32-bit machine, the [Microsoft C++ Visual Build Tools][1] are required to compile Nescient's C extensions.

> **Linux:** Installation may require root permissions, or running `python3 -m pip install nescient --user` instead. The latter may require export `~/.local/bin` to `PATH` to run Nescient from the command line.

### From GitHub Releases
Run `<python> -m pip install git+git://github.com/arantonitis/nescient.git@<tag>`, where `<tag>` is like `v0.9.0`, etc.

[1]: <https://visualstudio.microsoft.com/visual-cpp-build-tools/>
