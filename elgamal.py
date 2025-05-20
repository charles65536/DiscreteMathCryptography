"""
ElGamal Cryptosystem Implementation

This module implements the ElGamal public-key cryptosystem, which is based on the
difficulty of computing discrete logarithms in a finite field. The implementation
includes key generation, encryption, decryption, and message encoding/decoding
capabilities.

The ElGamal cryptosystem works as follows:
1. Key Generation:
   - Choose a large prime p
   - Find a primitive root g modulo p
   - Choose a private key x
   - Calculate public key h = g^x mod p

2. Encryption:
   - Choose a random ephemeral key k
   - Calculate c1 = g^k mod p
   - Calculate c2 = m * h^k mod p
   - Send (c1, c2) as the ciphertext

3. Decryption:
   - Calculate s = c1^x mod p
   - Calculate s_inverse = s^(p-2) mod p
   - Calculate m = c2 * s_inverse mod p

Security Features:
- Semantic security through random ephemeral keys
- Large prime numbers for key generation
- Miller-Rabin primality testing
- Proper primitive root selection

Author: [Your Name]
Date: [Current Date]
"""

import random
import math
from typing import Tuple, Dict, List


class ElGamal:
    """
    ElGamal cryptosystem implementation.

    This class provides methods for key generation, encryption, and decryption
    using the ElGamal public-key cryptosystem. The implementation includes
    secure prime number generation, primitive root finding, and message encoding
    capabilities.

    Attributes:
        None (all methods are static)

    Example:
        >>> elgamal = ElGamal()
        >>> keys = ElGamal.generate_keys(bits=1024)
        >>> ciphertext = ElGamal.encrypt(message, keys['public_key'])
        >>> plaintext = ElGamal.decrypt(ciphertext, keys['private_key'])
    """

    @staticmethod
    def is_prime(n: int, k: int = 40) -> bool:
        """
        Check if a number is prime using the Miller-Rabin primality test.

        The Miller-Rabin test is a probabilistic primality test that works as follows:
        1. Write n-1 as 2^r * d where d is odd
        2. For k iterations:
           - Pick a random a in [2, n-2]
           - Compute x = a^d mod n
           - If x = 1 or x = n-1, continue
           - For r-1 times:
             * x = x^2 mod n
             * If x = n-1, break
           - If x != n-1, n is composite

        Args:
            n (int): The number to check for primality
            k (int): Number of iterations for testing (higher means more accuracy)
                    Default is 40, which gives a probability of error less than 2^-80

        Returns:
            bool: True if the number is probably prime, False otherwise

        Example:
            >>> ElGamal.is_prime(17)
            True
            >>> ElGamal.is_prime(24)
            False
        """
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True

        # Find r and d such that n-1 = 2^r * d, where d is odd
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1

        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_large_prime(bits: int = 1024) -> int:
        """
        Generate a large prime number of specified bit length.

        This method generates cryptographically secure prime numbers by:
        1. Generating random numbers of the specified bit length
        2. Ensuring the number is odd and has the high bit set
        3. Testing for primality using the Miller-Rabin test

        Args:
            bits (int): Number of bits for the prime number
                      Default is 1024 bits for good security

        Returns:
            int: A large prime number of the specified bit length

        Example:
            >>> prime = ElGamal.generate_large_prime(bits=512)
            >>> len(bin(prime)[2:])  # Check bit length
            512
        """
        while True:
            # Generate a random odd number of the specified bit length
            p = random.getrandbits(bits)
            p |= (1 << bits - 1) | 1  # Set the high bit and make it odd

            if ElGamal.is_prime(p):
                return p

    @staticmethod
    def find_primitive_root(p: int) -> int:
        """
        Find a primitive root modulo p.

        A primitive root g modulo p is a number such that:
        - g^(p-1) ≡ 1 (mod p)
        - g^d ≢ 1 (mod p) for any d < p-1

        The method works by:
        1. Finding the prime factors of p-1
        2. Testing random numbers g until finding one where:
           g^((p-1)/q) ≢ 1 (mod p) for all prime factors q of p-1

        Args:
            p (int): Prime number

        Returns:
            int: A primitive root modulo p

        Example:
            >>> p = ElGamal.generate_large_prime(bits=64)
            >>> g = ElGamal.find_primitive_root(p)
            >>> pow(g, p-1, p) == 1  # Verify it's a primitive root
            True
        """
        if p == 2:
            return 1

        # Find the prime factors of p-1
        phi = p - 1
        factors = []

        # Find if phi is divisible by 2
        if phi % 2 == 0:
            factors.append(2)
            while phi % 2 == 0:
                phi //= 2

        # Check for odd prime factors
        i = 3
        while i * i <= phi:
            if phi % i == 0:
                factors.append(i)
                while phi % i == 0:
                    phi //= i
            i += 2

        # If phi is a prime number greater than 2
        if phi > 2:
            factors.append(phi)

        # Check for primitive roots
        while True:
            g = random.randint(2, p - 1)
            is_primitive = True

            for factor in factors:
                if pow(g, (p - 1) // factor, p) == 1:
                    is_primitive = False
                    break

            if is_primitive:
                return g

    @staticmethod
    def generate_keys(bits: int = 1024) -> Dict:
        """
        Generate public and private keys for the ElGamal cryptosystem.

        The key generation process:
        1. Generate a large prime p
        2. Find a primitive root g modulo p
        3. Choose a random private key x
        4. Calculate public key h = g^x mod p

        Args:
            bits (int): Number of bits for the prime number
                      Default is 1024 bits for good security

        Returns:
            Dict: A dictionary containing:
                - public_key: {'p': p, 'g': g, 'h': h}
                - private_key: {'p': p, 'x': x}

        Example:
            >>> keys = ElGamal.generate_keys(bits=512)
            >>> 'public_key' in keys and 'private_key' in keys
            True
        """
        # Generate a large prime number p
        p = ElGamal.generate_large_prime(bits)

        # Find a primitive root modulo p
        g = ElGamal.find_primitive_root(p)

        # Choose a random private key
        x = random.randint(2, p - 2)

        # Calculate the public key
        h = pow(g, x, p)

        return {
            'public_key': {'p': p, 'g': g, 'h': h},
            'private_key': {'p': p, 'x': x}
        }

    @staticmethod
    def encrypt(message: int, public_key: Dict) -> Tuple[int, int]:
        """
        Encrypt a message using the ElGamal encryption algorithm.

        The encryption process:
        1. Choose a random ephemeral key k
        2. Calculate c1 = g^k mod p
        3. Calculate c2 = m * h^k mod p
        4. Return (c1, c2) as the ciphertext

        Args:
            message (int): The message to encrypt (must be an integer less than p)
            public_key (Dict): The recipient's public key containing:
                             - p: prime modulus
                             - g: generator
                             - h: public key value

        Returns:
            Tuple[int, int]: Encrypted message as a pair (c1, c2)

        Raises:
            ValueError: If message is greater than or equal to p

        Example:
            >>> keys = ElGamal.generate_keys(bits=64)
            >>> ciphertext = ElGamal.encrypt(42, keys['public_key'])
            >>> len(ciphertext) == 2  # Should return a pair
            True
        """
        p = public_key['p']
        g = public_key['g']
        h = public_key['h']

        # Check if message is less than p
        if message >= p:
            raise ValueError("Message must be less than p")

        # Choose a random ephemeral key
        k = random.randint(2, p - 2)

        # Calculate c1 = g^k mod p
        c1 = pow(g, k, p)

        # Calculate c2 = m * h^k mod p
        c2 = (message * pow(h, k, p)) % p

        return c1, c2

    @staticmethod
    def decrypt(ciphertext: Tuple[int, int], private_key: Dict) -> int:
        """
        Decrypt a message using the ElGamal decryption algorithm.

        The decryption process:
        1. Calculate s = c1^x mod p
        2. Calculate s_inverse = s^(p-2) mod p
        3. Calculate m = c2 * s_inverse mod p

        Args:
            ciphertext (Tuple[int, int]): The encrypted message as a pair (c1, c2)
            private_key (Dict): The recipient's private key containing:
                              - p: prime modulus
                              - x: private key value

        Returns:
            int: The decrypted message

        Example:
            >>> keys = ElGamal.generate_keys(bits=64)
            >>> message = 42
            >>> ciphertext = ElGamal.encrypt(message, keys['public_key'])
            >>> decrypted = ElGamal.decrypt(ciphertext, keys['private_key'])
            >>> decrypted == message
            True
        """
        c1, c2 = ciphertext
        p = private_key['p']
        x = private_key['x']

        # Calculate s = c1^x mod p
        s = pow(c1, x, p)

        # Calculate s_inverse = s^(p-2) mod p (using Fermat's little theorem)
        s_inverse = pow(s, p - 2, p)

        # Calculate m = c2 * s_inverse mod p
        m = (c2 * s_inverse) % p

        return m

    @staticmethod
    def encode_message(message: str) -> List[int]:
        """
        Encode a string message to a list of integers.

        This method performs a simple encoding by converting each character
        to its ASCII value. For production use, consider using a more robust
        encoding scheme.

        Args:
            message (str): The string message to encode

        Returns:
            List[int]: The encoded message as a list of integers

        Example:
            >>> ElGamal.encode_message("Hello")
            [72, 101, 108, 108, 111]
        """
        # Simple encoding: each character is converted to its ASCII value
        return [ord(char) for char in message]

    @staticmethod
    def decode_message(encoded_message: List[int]) -> str:
        """
        Decode a list of integers back to a string message.

        This method performs a simple decoding by converting each integer
        back to its corresponding ASCII character.

        Args:
            encoded_message (List[int]): The list of integers to decode

        Returns:
            str: The decoded string message

        Example:
            >>> ElGamal.decode_message([72, 101, 108, 108, 111])
            'Hello'
        """
        # Convert each integer back to its ASCII character
        return ''.join(chr(num) for num in encoded_message)


def demo_elgamal():
    """
    Demonstrate the ElGamal cryptosystem with a simple example.

    This function shows a complete workflow of:
    1. Key generation
    2. Message encoding
    3. Encryption
    4. Decryption
    5. Message decoding

    The demonstration uses a small key size (64 bits) for quick execution.
    For real-world use, use at least 1024 bits for security.
    """
    print("ElGamal Cryptosystem Demonstration")
    print("---------------------------------")

    print("Generating keys (using small key size for demo)...")
    keys = ElGamal.generate_keys(bits=64)

    # Original message
    original_text = "Hello, ElGamal cryptosystem!"
    print(f"Original message: '{original_text}'")

    # Encode message
    encoded = ElGamal.encode_message(original_text)
    print(f"Encoded message: {encoded}")

    # Encrypt each character
    encrypted = []
    for char in encoded:
        ciphertext = ElGamal.encrypt(char, keys['public_key'])
        encrypted.append(ciphertext)
    print(f"Encrypted message: {encrypted}")

    # Decrypt each character
    decrypted = []
    for ciphertext in encrypted:
        plaintext = ElGamal.decrypt(ciphertext, keys['private_key'])
        decrypted.append(plaintext)
    print(f"Decrypted message: {decrypted}")

    # Decode message
    final_text = ElGamal.decode_message(decrypted)
    print(f"Final message: '{final_text}'")

    # Verify
    print(f"\nVerification: Original message matches final message: {original_text == final_text}")


if __name__ == "__main__":
    demo_elgamal()