"""
Elliptic Curve Cryptography (ECC) Implementation

This module implements Elliptic Curve Cryptography operations including:
- Point addition and scalar multiplication on elliptic curves
- Key pair generation
- Encryption and decryption using ECC
- Support for multiple NIST curves (P-192, P-224, P-256, P-384, P-521)

The implementation follows the ECC algorithm:
1. Choose an elliptic curve and a base point G
2. Generate a private key (random number) and corresponding public key
3. Use the public key for encryption and private key for decryption

Author: [Your Name]
Date: [Current Date]
"""

import hashlib
import random
import time

# NIST curve parameters for various security levels
curves = {
    'P-192': {
        'p': 0xfffffffffffffffffffffffffffffffeffffffffffffffff,
        'a': -3,
        'b': 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
        'G': (
            0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
            0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
        ),
        'n': 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
    },
    'P-224': {
        'p': 0xffffffffffffffffffffffffffffffff000000000000000000000001,
        'a': -3,
        'b': 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
        'G': (
            0xb70e0cbcdb6bb4bf7f321390b94a03c1d356c21122343280d6115c1d,
            0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34
        ),
        'n': 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d
    },
    'P-256': {
        'p': 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        'a': -3,
        'b': 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        'G': (
            0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
            0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        ),
        'n': 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    },
    'P-384': {
        'p': int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16),
        'a': -3,
        'b': int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
        'G': (
            int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
            int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)
        ),
        'n': int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
    },
    'P-521': {
        'p': 2**521 - 1,
        'a': -3,
        'b': int("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
        'G': (
            int("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
            int("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16)
        ),
        'n': int("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16)
    }
}

def mod_inverse(a: int, m: int) -> int:
    """
    Calculate the modular multiplicative inverse using Fermat's Little Theorem.
    
    Args:
        a (int): The number to find the inverse of
        m (int): The modulus (must be prime)
        
    Returns:
        int: The modular multiplicative inverse of a modulo m
        
    Note:
        This implementation assumes m is prime and uses Fermat's Little Theorem:
        a^(m-1) ≡ 1 (mod m) => a^(m-2) ≡ a^(-1) (mod m)
    """
    return pow(a, m - 2, m)

def point_add(P: tuple, Q: tuple, a: int, p: int) -> tuple:
    """
    Add two points on an elliptic curve.
    
    Args:
        P (tuple): First point (x1, y1)
        Q (tuple): Second point (x2, y2)
        a (int): Curve parameter a
        p (int): Prime modulus
        
    Returns:
        tuple: Resulting point (x3, y3)
        
    Note:
        Implements the elliptic curve point addition formula:
        - If P = O (point at infinity), return Q
        - If Q = O, return P
        - If P = -Q, return O
        - Otherwise, use the standard point addition formulas
    """
    if P == (0, 0): return Q
    if Q == (0, 0): return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 == y2:
        l = (3 * x1 * x1 + a) * mod_inverse(2 * y1, p) % p
    else:
        l = (y2 - y1) * mod_inverse((x2 - x1) % p, p) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_multiply(k: int, P: tuple, a: int, p: int) -> tuple:
    """
    Multiply a point on an elliptic curve by a scalar using the double-and-add algorithm.
    
    Args:
        k (int): Scalar multiplier
        P (tuple): Point to multiply (x, y)
        a (int): Curve parameter a
        p (int): Prime modulus
        
    Returns:
        tuple: Resulting point kP
        
    Note:
        Implements the double-and-add algorithm for efficient scalar multiplication:
        1. Start with result = O (point at infinity)
        2. For each bit in k:
           - Double the result
           - If bit is 1, add P to result
    """
    R = (0, 0)
    while k:
        if k & 1:
            R = point_add(R, P, a, p)
        P = point_add(P, P, a, p)
        k >>= 1
    return R

def generate_key_pair(G: tuple, n: int, a: int, p: int) -> tuple:
    """
    Generate an ECC key pair.
    
    Args:
        G (tuple): Base point (generator)
        n (int): Order of the base point
        a (int): Curve parameter a
        p (int): Prime modulus
        
    Returns:
        tuple: (private_key, public_key) where:
            - private_key is a random integer in [1, n-1]
            - public_key is the point private_key * G
    """
    priv = random.randint(1, n - 1)
    pub = scalar_multiply(priv, G, a, p)
    return priv, pub

def derive_xor_key(shared_point: tuple, length: int) -> bytes:
    """
    Derive a symmetric key from a shared point using SHA-256.
    
    Args:
        shared_point (tuple): The shared point (x, y)
        length (int): Desired key length in bytes
        
    Returns:
        bytes: Derived key of specified length
        
    Note:
        Uses the x-coordinate of the shared point to generate a key
        through repeated hashing with SHA-256
    """
    x_bytes = shared_point[0].to_bytes((shared_point[0].bit_length() + 7) // 8, 'big')
    hash_bytes = hashlib.sha256(x_bytes).digest()
    while len(hash_bytes) < length:
        hash_bytes += hashlib.sha256(hash_bytes).digest()
    return hash_bytes[:length]

def xor_data(data: bytes, key: bytes) -> bytes:
    """
    Perform XOR operation between data and key.
    
    Args:
        data (bytes): Data to encrypt/decrypt
        key (bytes): Key to use for XOR operation
        
    Returns:
        bytes: Result of XOR operation
    """
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def ecc_encrypt(message: bytes, pubkey: tuple, G: tuple, n: int, a: int, p: int) -> dict:
    """
    Encrypt a message using ECC.
    
    Args:
        message (bytes): Message to encrypt
        pubkey (tuple): Recipient's public key
        G (tuple): Base point
        n (int): Order of the base point
        a (int): Curve parameter a
        p (int): Prime modulus
        
    Returns:
        dict: {
            'ephemeral_pub': ephemeral public key,
            'ciphertext': encrypted message
        }
        
    Note:
        Uses ephemeral key pair for each encryption to ensure
        semantic security (same message encrypted twice produces
        different ciphertexts)
    """
    ephemeral_priv, ephemeral_pub = generate_key_pair(G, n, a, p)
    shared_point = scalar_multiply(ephemeral_priv, pubkey, a, p)
    key = derive_xor_key(shared_point, len(message))
    ciphertext = xor_data(message, key)
    return {
        'ephemeral_pub': ephemeral_pub,
        'ciphertext': ciphertext
    }

def ecc_decrypt(bundle: dict, privkey: int, a: int, p: int) -> bytes:
    """
    Decrypt a message using ECC.
    
    Args:
        bundle (dict): {
            'ephemeral_pub': ephemeral public key,
            'ciphertext': encrypted message
        }
        privkey (int): Recipient's private key
        a (int): Curve parameter a
        p (int): Prime modulus
        
    Returns:
        bytes: Decrypted message
        
    Note:
        Uses the recipient's private key and the ephemeral public key
        to derive the same shared point used in encryption
    """
    ephemeral_pub = bundle['ephemeral_pub']
    ciphertext = bundle['ciphertext']
    shared_point = scalar_multiply(privkey, ephemeral_pub, a, p)
    key = derive_xor_key(shared_point, len(ciphertext))
    return xor_data(ciphertext, key)

if __name__ == "__main__":
    # Read input message
    with open("input.txt", "rb") as f:
        plaintext = f.read()

    # Test each NIST curve
    for name, params in curves.items():
        print(f"\nTesting Curve: {name}")
        p, a, b, G, n = params['p'], params['a'], params['b'], params['G'], params['n']

        # Measure key generation time
        t = time.time()
        priv, pub = generate_key_pair(G, n, a, p)
        t_gen = time.time() - t

        # Measure encryption time
        t0 = time.time()
        enc = ecc_encrypt(plaintext, pub, G, n, a, p)
        t_enc = time.time() - t0

        # Measure decryption time
        t1 = time.time()
        dec = ecc_decrypt(enc, priv, a, p)
        t_dec = time.time() - t1

        # Display results
        print("Decrypted text:", dec.decode('utf-8'))
        print(f"Generation time: {t_gen:.6f} seconds")
        print(f"Encryption time: {t_enc:.6f} seconds")
        print(f"Decryption time: {t_dec:.6f} seconds")
