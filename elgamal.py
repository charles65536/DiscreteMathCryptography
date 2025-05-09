import random
import math
from typing import Tuple, Dict, List


class ElGamal:
    """
    ElGamal cryptosystem implementation.

    This class provides methods for key generation, encryption, and decryption
    using the ElGamal public-key cryptosystem.
    """

    @staticmethod
    def is_prime(n: int, k: int = 40) -> bool:
        """
        Check if a number is prime using the Miller-Rabin primality test.

        Args:
            n: The number to check for primality
            k: Number of iterations for testing (higher means more accuracy)

        Returns:
            bool: True if the number is probably prime, False otherwise
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

        Args:
            bits: Number of bits for the prime number

        Returns:
            int: A large prime number
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

        Args:
            p: Prime number

        Returns:
            int: A primitive root modulo p
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

        Args:
            bits: Number of bits for the prime number

        Returns:
            Dict: A dictionary containing public and private keys
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

        Args:
            message: The message to encrypt (must be an integer less than p)
            public_key: The recipient's public key

        Returns:
            Tuple[int, int]: Encrypted message as a pair (c1, c2)
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

        Args:
            ciphertext: The encrypted message as a pair (c1, c2)
            private_key: The recipient's private key

        Returns:
            int: The decrypted message
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

        Args:
            message: The string message to encode

        Returns:
            List[int]: The encoded message as a list of integers
        """
        # Simple encoding: each character is converted to its ASCII value
        return [ord(char) for char in message]

    @staticmethod
    def decode_message(encoded_message: List[int]) -> str:
        """
        Decode a list of integers back to a string message.

        Args:
            encoded_message: The list of integers to decode

        Returns:
            str: The decoded string message
        """
        # Convert each integer back to its ASCII character
        return ''.join(chr(num) for num in encoded_message)


def demo_elgamal():
    """
    Demonstrate the ElGamal cryptosystem with a simple example.
    """
    print("ElGamal Cryptosystem Demonstration")
    print("---------------------------------")

    print("Generating keys (using small key size for demo)...")
    keys = ElGamal.generate_keys(bits=64)

    # Original message
    original_text = "Hello, ElGamal cryptosystem!"
    print(f"Original message: '{original_text}'")

    # Encode the message
    encoded_message = ElGamal.encode_message(original_text)
    print(f"Encoded message (as integers): {encoded_message}")

    # Encrypt each part of the message
    print("Encrypting message...")
    encrypted_message = [ElGamal.encrypt(m, keys['public_key']) for m in encoded_message]
    print(f"Encrypted message: {encrypted_message}")

    # Decrypt the message
    print("Decrypting message...")
    decrypted_integers = [ElGamal.decrypt(c, keys['private_key']) for c in encrypted_message]
    print(f"Decrypted integers: {decrypted_integers}")

    # Decode the message
    decrypted_text = ElGamal.decode_message(decrypted_integers)
    print(f"Decrypted message: '{decrypted_text}'")

    # Verify the decryption worked correctly
    assert decrypted_text == original_text
    print("Verification successful: Original and decrypted messages match!")


if __name__ == "__main__":
    demo_elgamal()