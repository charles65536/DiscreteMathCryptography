import random
from math import gcd
import string
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

def insert_random_letters(s):
    result = []
    for i in range(0, len(s), 2):
        chunk = s[i:i+2]
        result.append(chunk)
        if i + 2 < len(s):  
            rand_char = random.choice(string.ascii_letters)
            result.append(rand_char)
    return ''.join(result)

def recover_original_from_inserted(s):
    result = []
    for i in range(0, len(s), 3):
        chunk = s[i:i+2]  
        result.append(chunk)
    return ''.join(result)


def encrypt(public_keys, plaintext):
    plaintext = insert_random_letters(plaintext)
    min_n = min(n for e, n in public_keys)
    block_size = find_block_size(plaintext, min_n)

    cipher = []
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        key_index = (i // block_size) % len(public_keys)
        e, n = public_keys[key_index]
        block_num = int(''.join(f"{ord(c):03}" for c in block))
        cipher.append(pow(block_num, e, n)) 

    return cipher, block_size



def decrypt(private_keys, ciphertext, block_size):
    plaintext = ""

    for i, c in enumerate(ciphertext):
        key_index = i % len(private_keys)
        d, n = private_keys[key_index]
        num = pow(c, d, n)
        block_str = str(num).zfill(3 * block_size)
        chars = [chr(int(block_str[i:i+3])) for i in range(0, len(block_str), 3)]
        plaintext += ''.join(chars)

    return recover_original_from_inserted(plaintext)



if __name__ == "__main__":
    pq_list = [(1009, 1013), (1031, 1033), (1061, 1063)]
    public_keys = []
    private_keys = []

    for p, q in pq_list:
        pub, priv = generate_keypair(p, q)
        public_keys.append(pub)
        private_keys.append(priv)

    message = (
        "In the field of cryptography, RSA is one of the first public-key cryptosystems and is widely used "
        "for secure data transmission. The security of RSA relies on the practical difficulty of factoring the "
        "product of two large prime numbers, the factoring problem. RSA stands for Rivest, Shamir, and Adleman, "
        "who first publicly described it in 1977. The algorithm uses a pair of keys: a public key, which is known "
        "to everyone, and a private key, which is known only to the recipient of the message."
    )

    encrypted, block_size = encrypt(public_keys, message)
    print("block_size:", block_size)
    print("encrypted:", encrypted)

    decrypted = decrypt(private_keys, encrypted, block_size)
    print("decrypted:", decrypted)

