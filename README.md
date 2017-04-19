# ![logo](https://github.com/aantonitis/nescient/blob/master/Nessie.png "Logo") Nescient

*nescient, n. (nesh-int) - from Latin 'unknowing', 'hidden'*  

Python program for packing/unpacking encrypted, salted, and authenticated single-file containers  

Primarily uses the AES block cipher for encryption, as well as SHA-256 (currently) and GCM tags (planned) for authentication.  

While all code is begun in Python, certain attention has been paid to Cythonizing critical modules to improve speed of encryption. In future, use of Nescient under PyPy 3.5 will be tested to see whether an additional speedup can be gained.

## Prerequisites
Support only guaranteed for Python version 3.5 or higher. Installing via ```pip``` will require ```setuptools```, likely already present on the target system.

## Installation
### From PyPI
Simply run ```pip3 install nescient``` to install the latest stable version.
### From source distributions
Download one of the tarballs from the release tags, or from the ```/dist/``` folder, and run ```pip3 install path-to-tarball```.
### From latest source
Download the entire repo, and run ```python3 setup.py install``` from its root directory.

## Usage
Once installed, can be run from the terminal simply by running ```nescient```, or for help options ```nescient -h```.
