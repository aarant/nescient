# ![logo](https://github.com/aantonitis/nescient/blob/master/Nessie.png "Logo") Nescient

*nescient, n. - from Latin 'unknowing', 'hidden'*  

Python3 program for (un)packing encrypted, salted, and authenticated single-file containers.  

Primarily uses the AES block cipher for encryption, as well as SHA-256 (currently) and GCM tags (planned) for authentication.  

While all code is begun in Python, certain attention has been paid to Cythonizing critical modules to improve speed of encryption. In future, use of Nescient under PyPy 3.5 will be tested to see whether an additional speedup can be gained.

## Prerequisites
Requires Python version 3.5 or higher. Should run on any platform that supports the interpreter, with the exception of Windows, which lacks a native ```curses``` library (this dependency will be fixed later).

## Installation
Can be installed by downloading the latest source distribution and running ```pip3 install 'path-to-tarball'```, or, alternatively,  ```pip3 install nescient```, from the Python Package Index (PyPI).

## Usage
Once installed, can be run from the terminal simply by running ```nescient```, or for help options ```nescient -h```
