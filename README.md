[pypi]: <https://pypi.org/project/Nescient/>
[license]: <https://github.com/arantonitis/nescient/tree/master/LICENSE>

# ![nessie](https://raw.githubusercontent.com/arantonitis/nescient/master/nescient/nessie.png) Nescient
[![PyPI badge](https://img.shields.io/pypi/v/nescient.svg)][pypi]
[![License badge](https://img.shields.io/github/license/arantonitis/nescient.svg)][license]

*nescient, n. (nesh-int) - from Latin 'unknown', 'hidden'*

Pack files to and from encrypted, authenticated containers.

Nescient provides an easy-to-use, secure, and efficient means of file or memory level encryption.

Use cases include:

* Backing up multiple files to a reliable yet insecure location, like some cloud storage providers.

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

```
$ python -m pip install nescient --user
```

> **Windows:** You may need to install the [Microsoft C++ Visual Build Tools][1] to compile Nescient's C extensions.

### From Releases
Run `<python> -m pip install git+git://github.com/arantonitis/nescient.git@<tag>`, where `<tag>` is like `v0.9.0`, etc.

## Usage
Nescient has a GUI mode, which can be run by running `nescient-ui`, or `nescient` with no arguments.

Nescient packs/unpacks file patterns into `.nesc` containers:
```
$ nescient pack file1 file2
$ nescient pack *.png
$ nescient unpack file1.nesc
```

Command line help can be viewed with `nescient -h`.

## Development
Nescient versioning functions on a `MAJOR.MINOR.PATCH.[DEVELOP]` model.
Only stable, non development releases will be published to PyPI.
Because Nescient is still a beta project, the `MAJOR` increment will be 0.
Minor increments represent new features. 
Patch increments represent problems fixed with existing features.

Planned features include:

* New cipher modes for existing algorithms, like the GCM authenticated mode, and additional encryption algorithms.

* Integrated compression when packing files.

* GUI mode enhancements.

* Documentation.

[1]: <https://visualstudio.microsoft.com/visual-cpp-build-tools/>
