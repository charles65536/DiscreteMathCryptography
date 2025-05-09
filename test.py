import random
from math import gcd
import time
import matplotlib.pyplot as plt

# RSA 相关代码
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception('inverse does not exist')
    return x % m

def generate_rsa_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p and q must be prime")
    if p == q:
        raise ValueError("p and q cannot be equal")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = modinv(e, phi)

    return (e, n), (d, n)

def generate_prime_number(length=32):
    prime_candidate = 4
    while not is_prime(prime_candidate):
        prime_candidate = random.getrandbits(length)
        prime_candidate |= (1 << length - 1) | 1  # Set the highest and lowest bits
    return prime_candidate

def encrypt_rsa(public_key, plaintext):
    e, n = public_key
    return pow(plaintext, e, n)

def decrypt_rsa(private_key, ciphertext):
    d, n = private_key
    return pow(ciphertext, d, n)

# ElGamal 相关代码
class ElGamal:
    @staticmethod
    def is_prime(n: int, k: int = 40) -> bool:
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True

        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1

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
    def generate_large_prime(bits: int = 32) -> int:
        while True:
            p = random.getrandbits(bits)
            p |= (1 << bits - 1) | 1
            if ElGamal.is_prime(p):
                return p

    @staticmethod
    def find_primitive_root(p: int) -> int:
        if p == 2:
            return 1

        phi = p - 1
        factors = []

        if phi % 2 == 0:
            factors.append(2)
            while phi % 2 == 0:
                phi //= 2

        i = 3
        while i * i <= phi:
            if phi % i == 0:
                factors.append(i)
                while phi % i == 0:
                    phi //= i
            i += 2

        if phi > 2:
            factors.append(phi)

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
    def generate_keys(bits: int = 32) -> dict:
        p = ElGamal.generate_large_prime(bits)
        g = ElGamal.find_primitive_root(p)
        x = random.randint(2, p - 2)
        h = pow(g, x, p)

        return {
            'public_key': {'p': p, 'g': g, 'h': h},
            'private_key': {'p': p, 'x': x}
        }

    @staticmethod
    def encrypt(message: int, public_key: dict) -> tuple:
        p = public_key['p']
        g = public_key['g']
        h = public_key['h']

        if message >= p:
            raise ValueError("Message must be less than p")

        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
        c2 = (message * pow(h, k, p)) % p

        return c1, c2

    @staticmethod
    def decrypt(ciphertext: tuple, private_key: dict) -> int:
        c1, c2 = ciphertext
        p = private_key['p']
        x = private_key['x']

        s = pow(c1, x, p)
        s_inverse = pow(s, p - 2, p)
        m = (c2 * s_inverse) % p

        return m

def test_rsa_performance(key_sizes, num_trials):
    rsa_times = []
    for size in key_sizes:
        key_gen_total = 0
        encrypt_total = 0
        decrypt_total = 0
        
        for _ in range(num_trials):
            p = generate_prime_number(size // 2)
            q = generate_prime_number(size // 2)
            
            # Key generation time
            start = time.time()
            public_key, private_key = generate_rsa_keypair(p, q)
            key_gen_total += time.time() - start
            
            # Encryption and decryption time
            message = "Test message for RSA"
            message_int = int.from_bytes(message.encode(), 'big')
            
            start = time.time()
            ciphertext = encrypt_rsa(public_key, message_int)
            encrypt_total += time.time() - start
            
            start = time.time()
            decrypt_rsa(private_key, ciphertext)
            decrypt_total += time.time() - start
        
        rsa_times.append((
            key_gen_total / num_trials,
            encrypt_total / num_trials,
            decrypt_total / num_trials
        ))
    return rsa_times

def test_elgamal_performance(key_sizes, num_trials):
    elgamal_times = []
    for size in key_sizes:
        key_gen_total = 0
        encrypt_total = 0
        decrypt_total = 0
        
        for _ in range(num_trials):
            # Key generation time
            start = time.time()
            keys = ElGamal.generate_keys(bits=size)
            key_gen_total += time.time() - start
            
            # Encryption and decryption time
            message = "Test message for ElGamal"
            encoded_message = [ord(char) for char in message]
            
            start = time.time()
            encrypted_message = [ElGamal.encrypt(m, keys['public_key']) for m in encoded_message]
            encrypt_total += time.time() - start
            
            start = time.time()
            for c in encrypted_message:
                ElGamal.decrypt(c, keys['private_key'])
            decrypt_total += time.time() - start
        
        elgamal_times.append((
            key_gen_total / num_trials,
            encrypt_total / num_trials,
            decrypt_total / num_trials
        ))
    return elgamal_times

def compare_encryption_algorithms():
    key_sizes = [32, 48, 64]  # 测试32、48和64位密钥
    num_trials = 10  # 每个密钥大小进行10次实验

    rsa_times = test_rsa_performance(key_sizes, num_trials)
    elgamal_times = test_elgamal_performance(key_sizes, num_trials)

    rsa_key_gen, rsa_encrypt, rsa_decrypt = zip(*rsa_times)
    elg_key_gen, elg_encrypt, elg_decrypt = zip(*elgamal_times)

    plt.figure(figsize=(10, 6))
    plt.plot(key_sizes, rsa_key_gen, marker='o', label='RSA Key Generation')
    plt.plot(key_sizes, elg_key_gen, marker='s', label='ElGamal Key Generation')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Average Time (seconds)')
    plt.title('Key Generation Time Comparison')
    plt.legend()
    plt.grid(True)
    plt.savefig('key_gen_time_comparison.png')
    plt.show()

    plt.figure(figsize=(10, 6))
    plt.plot(key_sizes, rsa_encrypt, marker='o', label='RSA Encryption')
    plt.plot(key_sizes, elg_encrypt, marker='s', label='ElGamal Encryption')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Average Time (seconds)')
    plt.title('Encryption Time Comparison')
    plt.legend()
    plt.grid(True)
    plt.savefig('encryption_time_comparison.png')
    plt.show()

    plt.figure(figsize=(10, 6))
    plt.plot(key_sizes, rsa_decrypt, marker='o', label='RSA Decryption')
    plt.plot(key_sizes, elg_decrypt, marker='s', label='ElGamal Decryption')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Average Time (seconds)')
    plt.title('Decryption Time Comparison')
    plt.legend()
    plt.grid(True)
    plt.savefig('decryption_time_comparison.png')
    plt.show()


if __name__ == "__main__":
    compare_encryption_algorithms()
