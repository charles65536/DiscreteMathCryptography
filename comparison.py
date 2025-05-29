"""
Cryptographic Algorithm Performance Comparison

This module implements a performance comparison between RSA and ElGamal
cryptographic algorithms. It measures and compares the execution time of
key generation, encryption, and decryption operations for different key sizes.

The comparison includes:
1. Key generation time
2. Encryption time
3. Decryption time

Test cases use different key sizes (512, 1024, 2048 bits) with multiple trials
to ensure statistical significance.


"""

import random
import time

# ================== Utility Functions ==================
def is_prime(n: int, k: int = 20) -> bool:
    """
    Test if a number is prime using the Miller-Rabin primality test.
    
    Args:
        n (int): The number to test for primality
        k (int): Number of iterations for testing (higher means more accuracy)
                Default is 20, which gives a probability of error less than 2^-40
    
    Returns:
        bool: True if the number is probably prime, False otherwise
        
    Note:
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
    """
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
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

def generate_prime(bits: int) -> int:
    """
    Generate a large prime number of specified bit length.
    
    Args:
        bits (int): Number of bits for the prime number
        
    Returns:
        int: A large prime number of the specified bit length
        
    Note:
        The generated number will be:
        - Of the specified bit length
        - Odd (least significant bit set to 1)
        - Prime (tested using Miller-Rabin)
    """
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Set the high bit and make it odd
        if is_prime(p):
            return p

def extended_gcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean Algorithm implementation.
    
    Args:
        a (int): First integer
        b (int): Second integer
        
    Returns:
        tuple: (gcd, x, y) where gcd is the greatest common divisor,
               and x, y are integers satisfying ax + by = gcd(a, b)
    """
    if a == 0:
        return (b, 0, 1)
    g, y, x = extended_gcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a: int, m: int) -> int:
    """
    Calculate the modular multiplicative inverse of a modulo m.
    
    Args:
        a (int): The number to find the inverse of
        m (int): The modulus
        
    Returns:
        int: The modular multiplicative inverse of a modulo m,
             or None if the inverse does not exist
    """
    g, x, _ = extended_gcd(a, m)
    return x % m if g == 1 else None

# ================== RSA Implementation ==================
class RSA:
    """
    RSA (Rivest-Shamir-Adleman) implementation.
    
    This class provides methods for RSA key generation, encryption, and decryption.
    The implementation uses the standard RSA algorithm with a fixed public exponent
    of 65537 (0x10001).
    """
    
    @staticmethod
    def generate_keys(bits: int) -> dict:
        """
        Generate RSA key pair.
        
        Args:
            bits (int): Number of bits for the modulus n
            
        Returns:
            dict: {
                'public': (e, n),
                'private': (d, n),
                'time': key_generation_time_in_ms
            }
        """
        start = time.perf_counter()
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while p == q:
            q = generate_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537  # Standard public exponent
        d = modinv(e, phi)
        end = time.perf_counter()
        return {'public': (e, n), 'private': (d, n), 'time': (end - start) * 1000}

    @staticmethod
    def encrypt(m: int, public_key: tuple) -> int:
        """
        Encrypt a message using RSA.
        
        Args:
            m (int): Message to encrypt
            public_key (tuple): (e, n) public key pair
            
        Returns:
            int: Encrypted message c = m^e mod n
        """
        e, n = public_key
        return pow(m, e, n)

    @staticmethod
    def decrypt(c: int, private_key: tuple) -> int:
        """
        Decrypt a message using RSA.
        
        Args:
            c (int): Ciphertext to decrypt
            private_key (tuple): (d, n) private key pair
            
        Returns:
            int: Decrypted message m = c^d mod n
        """
        d, n = private_key
        return pow(c, d, n)

# ================== ElGamal Implementation ==================
class ElGamal:
    """
    ElGamal cryptosystem implementation.
    
    This class provides methods for ElGamal key generation, encryption, and decryption.
    The implementation uses the standard ElGamal algorithm with a random ephemeral key
    for each encryption.
    """
    
    @staticmethod
    def generate_keys(bits: int) -> dict:
        """
        Generate ElGamal key pair.
        
        Args:
            bits (int): Number of bits for the prime p
            
        Returns:
            dict: {
                'public': (p, g, h),
                'private': (p, x),
                'time': key_generation_time_in_ms
            }
        """
        start = time.perf_counter()
        p = generate_prime(bits)
        g = ElGamal.find_generator(p)
        x = random.randint(2, p - 2)
        h = pow(g, x, p)
        end = time.perf_counter()
        return {'public': (p, g, h), 'private': (p, x), 'time': (end - start) * 1000}

    @staticmethod
    def find_generator(p: int) -> int:
        """
        Find a generator (primitive root) modulo p.
        
        Args:
            p (int): Prime number
            
        Returns:
            int: A generator g modulo p
            
        Note:
            A generator g modulo p satisfies:
            - g^(p-1) ≡ 1 (mod p)
            - g^d ≢ 1 (mod p) for any d < p-1
        """
        phi = p - 1
        factors = set()
        temp = phi
        for i in range(2, 100):
            if temp % i == 0:
                factors.add(i)
                while temp % i == 0:
                    temp //= i
        for g in range(2, p):
            if all(pow(g, phi // f, p) != 1 for f in factors):
                return g
        return 2

    @staticmethod
    def encrypt(m: int, public_key: tuple) -> tuple:
        """
        Encrypt a message using ElGamal.
        
        Args:
            m (int): Message to encrypt
            public_key (tuple): (p, g, h) public key
            
        Returns:
            tuple: (c1, c2) where:
                c1 = g^k mod p
                c2 = m * h^k mod p
                k is a random ephemeral key
        """
        p, g, h = public_key
        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
        s = pow(h, k, p)
        c2 = (m * s) % p
        return (c1, c2)

    @staticmethod
    def decrypt(cipher: tuple, private_key: tuple) -> int:
        """
        Decrypt a message using ElGamal.
        
        Args:
            cipher (tuple): (c1, c2) ciphertext
            private_key (tuple): (p, x) private key
            
        Returns:
            int: Decrypted message m = c2 * (c1^x)^(-1) mod p
        """
        p, x = private_key
        c1, c2 = cipher
        s = pow(c1, x, p)
        s_inv = modinv(s, p)
        return (c2 * s_inv) % p

# ================== Performance Testing ==================
def test_performance() -> list:
    """
    Run performance tests for RSA and ElGamal algorithms.
    
    Tests are run for different key sizes with multiple trials:
    - 512 bits: 10 trials
    - 1024 bits: 5 trials
    - 2048 bits: 3 trials
    
    Returns:
        list: List of dictionaries containing test results for each key size
    """
    test_cases = [(512, 10), (1024, 5), (2048, 3)]
    results = []

    for bits, trials in test_cases:
        print(f"\nTesting {bits}-bit keys...")

        rsa_total = {'key_gen': 0, 'enc': 0, 'dec': 0}
        elg_total = {'key_gen': 0, 'enc': 0, 'dec': 0}

        for _ in range(trials):
            m = random.randint(1, 100)

            # RSA
            rsa_keys = RSA.generate_keys(bits)
            start = time.perf_counter()
            c = RSA.encrypt(m, rsa_keys['public'])
            rsa_total['enc'] += time.perf_counter() - start

            start = time.perf_counter()
            RSA.decrypt(c, rsa_keys['private'])
            rsa_total['dec'] += time.perf_counter() - start
            rsa_total['key_gen'] += rsa_keys['time']

            # ElGamal
            elg_keys = ElGamal.generate_keys(bits)
            start = time.perf_counter()
            c = ElGamal.encrypt(m, elg_keys['public'])
            elg_total['enc'] += time.perf_counter() - start

            start = time.perf_counter()
            ElGamal.decrypt(c, elg_keys['private'])
            elg_total['dec'] += time.perf_counter() - start
            elg_total['key_gen'] += elg_keys['time']

        results.append({
            'bits': bits,
            'rsa': {
                'key_gen': rsa_total['key_gen'] / trials,
                'enc': (rsa_total['enc'] / trials) * 1000,
                'dec': (rsa_total['dec'] / trials) * 1000
            },
            'elgamal': {
                'key_gen': elg_total['key_gen'] / trials,
                'enc': (elg_total['enc'] / trials) * 1000,
                'dec': (elg_total['dec'] / trials) * 1000
            }
        })

    return results

def print_results(results: list) -> None:
    """
    Print performance test results in a formatted table.
    
    Args:
        results (list): List of test results from test_performance()
    """
    print("\n{:=^60}".format(" Performance Test Results "))
    for res in results:
        bits = res['bits']
        print(f"\n{'-'*30}\nKey Size: {bits} bits\n{'-'*30}")
        print("{:<8} | {:<12} | {:<10} | {:<10}".format(
            "Algorithm", "Key Gen(ms)", "Enc(ms)", "Dec(ms)"))
        print("-"*50)
        print("RSA     | {:>11.3f} | {:>9.3f} | {:>9.3f}".format(
            res['rsa']['key_gen'], res['rsa']['enc'], res['rsa']['dec']))
        print("ElGamal | {:>11.3f} | {:>9.3f} | {:>9.3f}".format(
            res['elgamal']['key_gen'], res['elgamal']['enc'], res['elgamal']['dec']))

def print_conclusion(results: list) -> None:
    """
    Print conclusions from the performance test results.
    
    Args:
        results (list): List of test results from test_performance()
    """
    print("\n{:=^60}".format(" Conclusions "))

    def safe_div(a: float, b: float) -> float:
        """Safely divide two numbers, returning infinity if denominator is zero."""
        return a / b if b != 0 else float('inf')

    def format_ratio(r: float) -> str:
        """Format a ratio, handling infinity case."""
        return "infinity" if r == float('inf') else "{:.1f}".format(r)

    key_ratios = [safe_div(res['elgamal']['key_gen'], res['rsa']['key_gen']) for res in results]
    enc_ratios = [safe_div(res['elgamal']['enc'], res['rsa']['enc']) for res in results]
    dec_ratios = [safe_div(res['elgamal']['dec'], res['rsa']['dec']) for res in results]

    print(f"""1. Key Generation Speed:
   - RSA is approximately {format_ratio(sum(key_ratios)/len(key_ratios))}x faster than ElGamal (average)

2. Encryption Speed:
   - RSA is approximately {format_ratio(sum(enc_ratios)/len(enc_ratios))}x faster than ElGamal (average)

3. Decryption Speed:
   - RSA is approximately {format_ratio(sum(dec_ratios)/len(dec_ratios))}x faster than ElGamal (average)

Note: Test sample size: 512-bit (10 trials), 1024-bit (5 trials), 2048-bit (3 trials)
""")

# ================== Main Program Entry ==================
if __name__ == "__main__":
    results = test_performance()
    print_results(results)
    print_conclusion(results)
