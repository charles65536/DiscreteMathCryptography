"""
RSA Key Generation Module

This module implements the key generation process for RSA cryptography.
It provides functions for prime number testing, modular arithmetic operations,
and RSA key pair generation with key storage capabilities.

The implementation follows the RSA algorithm:
1. Choose two distinct prime numbers p and q
2. Calculate n = p * q
3. Calculate φ(n) = (p-1) * (q-1)
4. Choose public exponent e where 1 < e < φ(n) and e is coprime with φ(n)
5. Calculate private exponent d where d * e ≡ 1 (mod φ(n))

Author: [Your Name]
Date: [Current Date]
"""

import random
import os
import string
from math import gcd, isqrt
import json

# Path for storing generated keys
Path = " "

def is_prime(n: int) -> bool:
    """
    Test if a number is prime using trial division up to the square root.
    
    Args:
        n (int): The number to test for primality
        
    Returns:
        bool: True if n is prime, False otherwise
        
    Example:
        >>> is_prime(17)
        True
        >>> is_prime(24)
        False
    """
    if n < 2:
        return False
    for i in range(2, isqrt(n) + 1):
        if n % i == 0:
            return False
    return True

def extended_gcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean Algorithm implementation.
    Finds the greatest common divisor (gcd) of a and b, and integers x and y
    such that ax + by = gcd(a, b).
    
    Args:
        a (int): First integer
        b (int): Second integer
        
    Returns:
        tuple: (gcd, x, y) where gcd is the greatest common divisor,
               and x, y are integers satisfying ax + by = gcd(a, b)
               
    Example:
        >>> extended_gcd(48, 18)
        (6, -1, 3)
    """
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y

def modinv(a: int, m: int) -> int:
    """
    Calculate the modular multiplicative inverse of a modulo m.
    The modular multiplicative inverse of a modulo m is an integer x such that:
    a * x ≡ 1 (mod m)
    
    Args:
        a (int): The number to find the inverse of
        m (int): The modulus
        
    Returns:
        int: The modular multiplicative inverse of a modulo m
        
    Raises:
        Exception: If the inverse does not exist (when a and m are not coprime)
        
    Example:
        >>> modinv(3, 11)
        4
    """
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception('inverse does not exist')
    return x % m

def generate_keypair(p: int, q: int) -> tuple:
    """
    Generate an RSA key pair using two prime numbers.
    
    Args:
        p (int): First prime number
        q (int): Second prime number
        
    Returns:
        tuple: ((e, n), (d, n)) where:
            - e is the public exponent
            - d is the private exponent
            - n is the modulus (p * q)
            
    Raises:
        ValueError: If p or q are not prime, or if p equals q
        
    Example:
        >>> generate_keypair(11, 13)
        ((7, 143), (103, 143))
    """
    if not (is_prime(p) and is_prime(q)) or p == q:
        raise ValueError("Invalid primes")
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = modinv(e, phi)
    return (e, n), (d, n)

def save_keys(public_keys: list, private_keys: list) -> None:
    """
    Save generated RSA keys to files.
    
    Args:
        public_keys (list): List of public key pairs (e, n)
        private_keys (list): List of private key pairs (d, n)
        
    The keys are saved in two files:
    - public_keys.txt: Contains comma-separated e,n pairs
    - private_keys.txt: Contains JSON-encoded private keys
    
    Example:
        >>> save_keys([(7, 143)], [(103, 143)])
        # Creates public_keys.txt and private_keys.txt
    """
    with open(os.path.join(Path, "public_keys.txt"), "w") as f:
        for e, n in public_keys:
            f.write(f"{e},{n}\n")
    with open(os.path.join(Path, "private_keys.txt"), "w") as f:
        json.dump(private_keys, f)

if __name__ == "__main__":
    # Pre-defined prime number pairs for key generation
    pq_list = [(10000019, 10000103), (10000000019,
                                      10000000583), (10093, 1000000000169)]
    public_keys, private_keys = [], []
    
    # Generate key pairs for each prime pair
    for p, q in pq_list:
        pub, priv = generate_keypair(p, q)
        public_keys.append(pub)
        private_keys.append(priv)
        save_keys(public_keys, private_keys)

    # Display generated public keys
    print("\nPublic Keys:")
    for i, (e, n) in enumerate(public_keys):
        print(f"Key {i+1}: e = {e}, n = {n}")
