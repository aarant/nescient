# Nescient: A Python program for packing/unpacking encrypted, salted, and authenticated file containers.
# Copyright (C) 2018 Ariel Antonitis. Licensed under the MIT license.
#
# nescient/crypto/galois.py
""" Classes for creating and interacting with Galois fields (otherwise known as finite fields)

A galois field of order q exists iff q is a prime power.
Elements in fields are represented as integers in the range 0...q-1, or alternatively, polynomials of the form:
x_0*p^0+x_1*p^1+...+x_(n-1)*p^(n-1)
"""
# TODO: Make better class docstrings
import math


class GaloisField:
    """ Defines a finite field of order q=p**n, with optional generator g and irreducible polynomial r

    Elements are consider to be normal integers in the range 0...q-1 (inclusive)
    Can perform the standard operations (add, mult, exponentiation, inversion), optionally using lookup tables
    """
    def __init__(self, p, n=1, r=None, g=None, maxMem=2 ** 30):
        if p < 2 or n < 1:
            raise ValueError('Unable to instantiate a finite field with these arguments')
        self.p, self.n = p, n
        self.q = self.p ** self.n  # Order of the field
        self.f = range(self.q)  # Iterator for elements in the field
        self.g = g
        self.r = p if n == 1 else r  # Technically reduce by p if this is a prime field
        if r is None and n > 1:  # If an r was not provided and is required (n > 1), find one
            self.r = self.findR()
        self.expTable = {}
        self.logTable = {}
        self.haveTables = False
        # If the memory needed to make lookup tables is less than 1 GB (default), calculate them now
        if self.q * math.log(self.q, 2) / 8 <= maxMem:
            self.makeLookupTables()
            self.haveTables = True

    # Calculate the unique set of prime factors of n
    @staticmethod
    def prime_factors(n):
        i = 2
        factors = set()
        while i * i <= n:
            if n % i:
                i += 1
            else:
                n //= i
                factors.add(i)
        if n > 1:
            factors.add(n)
        return factors

    # Euclidean algorithm for gcd
    @staticmethod
    def gcd(a, b):
        while b > 0:
            a, b = b, a % b
        return a

    # Euler's totient function
    @staticmethod
    def phi(a):
        b = a - 1
        c = 0
        while b > 0:
            if not GaloisField.gcd(a, b) - 1:
                c += 1
            b -= 1
        return c

    # Given an element x, returns an n+1-element vector representing x as polynomials in GF(p)
    def intToPoly(self, x):
        return [(x // self.p ** i) % self.p for i in range(self.n + 1)]

    # Given a vector of polynomials in GF(p), return the corresponding element (as an integer)
    def polyToInt(self, poly):
        return sum([self.p ** i * poly[i] for i in range(len(poly))])

    # Generates exp & log lookup tables, for increased multiplication speed
    def makeLookupTables(self):
        if self.g is None or self.generate(self.g) is False:  # If a generator was not provided or was invalid, find one
            if self.n == 1:  # If this is a prime field we can find a generator faster than brute force
                pfs = GaloisField.prime_factors(self.q - 1)  # Calculate the prime factors of phi(p), equal to p-1
                for g in self.f:
                    s = set()
                    isGen = True
                    for pf in pfs:
                        y = self.pow(g, (self.q - 1) / pf)
                        if y in s or y == 1:
                            isGen = False
                            break
                        s.add(y)
                    if isGen:
                        self.generate(g, False)  # g is known to be valid, so no need to double check
                        self.g = g
                        return
            else:  # Otherwise use the brute force method
                for g in self.f:
                    if self.generate(g):  # When this is true, tables will be generated as as part of the method call
                        self.g = g
                        return
        else:
            return
        raise RuntimeError('Unable to find a generator for the specified field')

    # Returns whether g is a generator for the field, also updates exp and log tables accordingly
    def generate(self, g, check=True):
        if check:  # If using this method to check whether the generator is valid, use dictionaries
            self.expTable = {}
            self.logTable = {}
        else:  # Otherwise assume g is valid and use lists to optimize for speed
            self.expTable = [0] * self.q
            self.logTable = [0] * self.q
        y = 1
        for x in self.f:
            if check and y in self.logTable and x != self.q - 1:
                return False
            self.expTable[x] = y
            self.logTable[y] = x
            y = self.mult(g, y)
        if check and len(self.logTable) != self.q - 1:
            return False
        self.logTable[1] = 0
        return True

    # Attempts to find the smallest degree n irreducible polynomial over the field
    def findR(self):
        for r in range(self.q + self.p, self.q * self.p):  # Search only for degree n polynomials
            if self.isIrreducible(r):
                return r
        raise RuntimeError('Unable to find an irreducible polynomial for the specified field')

    # Checks whether a given polynomial is irreducible
    def isIrreducible(self, r):
        for i in range(self.p, self.q):
            if self.modP(r, i) == 0:
                return False
        return True

    # Multiplies two elements, without reducing if the product is outside of the field
    def multPoly(self, a, b):
        if self.n == 1:  # Multiplication in a prime field without reduction
            return a * b
        if self.p == 2:  # We can use bitwise operations when p==2
            # Multiply each polynomial via bit shifts and xors
            c = 0
            for i in range(self.n):
                if b & (1 << i):
                    c ^= a * 1 << i
            return c
        else:  # Otherwise operate on polynomial representations of integers
            p_a = self.intToPoly(a)
            p_b = self.intToPoly(b)
            p_c = [0] * 2 * self.n  # Need enough space for the x**n * x**n term
            # Multiply polynomials mod P (naively)
            for i in range(self.n):
                for j in range(self.n):
                    p_c[i + j] += p_a[i] * p_b[j]
                    p_c[i + j] %= self.p
            return self.polyToInt(p_c)

    # Calculates the remainder a mod b, performing subtraction of polynomials mod p
    # Optionally, continues until the remainder is below some bound
    def modP(self, a, b, bound=None):
        if self.n == 1:  # Mod in prime fields is easy!
            return a % b
        if bound is None:
            bound = b
        if self.p == 2:  # Mod in 2**n fields is also easy (bitwise)
            while a >= bound:
                aBits = int(math.log2(a))
                bBits = int(math.log2(b))
                a ^= b << (aBits - bBits)
            return a
        else:  # Otherwise use the slower polynomial method
            p_a = self.intToPoly(a)
            p_b = self.intToPoly(b)
            while a >= bound:
                aPits = int(math.log(a, self.p))
                bPits = int(math.log(b, self.p))
                for i in range(bPits + 1):
                    p_a[aPits - bPits + i] -= p_b[i]
                    p_a[aPits - bPits + i] %= self.p
                a = self.polyToInt(p_a)
            return a

    # Adds two elements in the field
    def add(self, a, b):
        if self.n == 1:  # Addition in a prime field is just modulo p
            return (a + b) % self.p
        if self.p == 2:  # Special case, when p=2, addition is bitwise XOR
            return (a ^ b) & (self.q - 1)
        else:  # Otherwise we need to break integers into polynomial representations and add modulo p
            a_p = self.intToPoly(a)
            b_p = self.intToPoly(b)
            c_p = [(a_p[i] + b_p[i]) % self.p for i in range(self.n)]
            return self.polyToInt(c_p)

    # Multiplies two elements in the field
    def mult(self, a, b):
        if self.haveTables:  # Use lookup tables if possible
            return 0 if (a == 0 or b == 0) else self.expTable[(self.logTable[a] + self.logTable[b]) % (self.q - 1)]
        else:  # Otherwise use the slower reduction method
            return self.modP(self.multPoly(a, b), self.r, bound=self.q)

    # Returns the multiplicative inverse of an element using lookup tables
    def inverse(self, x):
        if self.haveTables:  # Use lookup tables if possible
            # Technically speaking, 0 has no multiplicative inverse, so just define it as itself
            return 0 if x == 0 else self.expTable[self.q - 1 - self.logTable[x]]
        else:  # TODO Otherwise, well, give up (might do this later, there's an easy way for prime fields)
            raise NotImplementedError

    # Raise an element in the field to a power
    def pow(self, a, b):
        if self.haveTables:  # Use lookup tables if possible
            return 0 if a == 0 else self.expTable[(self.logTable[a] * b) % (self.q - 1)]
        elif self.n == 1:  # If this is a prime field use Python's modular exponentiation
            return pow(a, b, self.p)
        else:  # Otherwise use exponentiation by repeated squaring
            c = 1
            while b > 0:
                if b % 2 == 0:
                    a = self.mult(a, a)
                    b /= 2
                else:
                    c = self.mult(a, c)
                    b -= 1
            return c

    # Allows for grabbing GfElement representations by indexing
    def __getitem__(self, item):
        if 0 <= item < self.q:
            return GfElement(item, self)
        raise IndexError


class GfElement:
    """ Object representation of a GaloisField element.

    Allows one to perform intuitive operations on the elements and get the correct results
    """
    def __init__(self, val, f):
        assert (0 <= val < f.q)
        self.f = f
        self.val = val

    def __add__(self, other):
        assert (self.f == other.f)
        return self.f.add(self.val, other.val)

    def __mul__(self, other):
        assert (self.f == other.f)
        return self.f.mult(self.val, other.val)

    def __pow__(self, power):  # Note that power is considered to be an integer, not a GfElement
        return self.f.pow(self.val, power)

    def __invert__(self):
        return self.f.inverse(self.val)

    def __str__(self):
        return str(self.val)

    def __index__(self):
        return int(self.val)

    def __int__(self):
        return int(self.val)
