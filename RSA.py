import random
from math import gcd

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

def generate_keypair(p, q):
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

def find_block_size(plaintext, n):
    length = len(plaintext)
    for size in range(length, 0, -1):
        if length % size != 0:
            continue
        test_block = plaintext[0:size]
        test_value = int(''.join(f"{ord(c):03}" for c in test_block))
        if test_value < n:
            return size
    return 1

def encrypt(public_key, plaintext):
    e, n = public_key
    block_size = find_block_size(plaintext, n)
    cipher = []

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        block_num = int(''.join(f"{ord(c):03}" for c in block))
        cipher.append(pow(block_num, e, n))

    return cipher, block_size

def decrypt(private_key, ciphertext, block_size):
    d, n = private_key
    plaintext = ""

    for c in ciphertext:
        num = pow(c, d, n)
        block_str = str(num).zfill(3 * block_size)
        chars = [chr(int(block_str[i:i+3])) for i in range(0, len(block_str), 3)]
        plaintext += ''.join(chars)

    return plaintext

if __name__ == "__main__":
    p, q = 1009, 1013
    public_key, private_key = generate_keypair(p, q)

    message = (
        "In the field of cryptography, RSA is one of the first public-key cryptosystems and is widely used "
        "for secure data transmission. The security of RSA relies on the practical difficulty of factoring the "
        "product of two large prime numbers, the factoring problem. RSA stands for Rivest, Shamir, and Adleman, "
        "who first publicly described it in 1977. The algorithm uses a pair of keys: a public key, which is known "
        "to everyone, and a private key, which is known only to the recipient of the message."
    )

    encrypted, block_size = encrypt(public_key, message)
    print("block_size:", block_size)
    print("encrypted:", encrypted)

    decrypted = decrypt(private_key, encrypted, block_size)
    print("decrypted:", decrypted)
