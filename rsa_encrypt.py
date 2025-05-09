import random
import string
import os

Path = " "

def insert_random_letters(s):
    result = []
    for i in range(0, len(s), 2):
        chunk = s[i:i+2]
        result.append(chunk)
        if i + 2 < len(s):
            rand_char = random.choice(string.ascii_letters)
            result.append(rand_char)
    return ''.join(result)


def find_block_size(plaintext, n):
    for size in range(len(plaintext), 0, -1):
        if len(plaintext) % size != 0:
            continue
        test_block = plaintext[0:size]
        test_value = int(''.join(f"{ord(c):03}" for c in test_block))
        if test_value < n:
            return size
    return 1


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


if __name__ == "__main__":
    public_keys = []
    with open(os.path.join(Path, "public_keys.txt"), "r") as f:
        for line in f:
            e, n = map(int, line.strip().split(","))
            public_keys.append((e, n))


    # file input
    '''with open(os.path.join(Path, "message.txt"), "r", encoding="utf-8") as f:
            message = f.read().strip()'''

    # preset
    message = (
        "In the field of cryptography, RSA is one of the first public-key cryptosystems and is widely used "
        "for secure data transmission. The security of RSA relies on the practical difficulty of factoring the "
        "product of two large prime numbers, the factoring problem. RSA stands for Rivest, Shamir, and Adleman, "
        "who first publicly described it in 1977. The algorithm uses a pair of keys: a public key, which is known "
        "to everyone, and a private key, which is known only to the recipient of the message."
    )

    ciphertext, block_size = encrypt(public_keys, message)
    with open(os.path.join(Path, "ciphertext.txt"), "w") as f:
        f.write(str(block_size) + "\n")
        f.write(str(ciphertext))

    print("Encrypted and saved to ciphertext.txt")
