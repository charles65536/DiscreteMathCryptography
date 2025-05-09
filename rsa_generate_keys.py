import random
import os
import string
from math import gcd, isqrt
import json

Path = " "


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, isqrt(n) + 1):
        if n % i == 0:
            return False
    return True


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception('inverse does not exist')
    return x % m


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)) or p == q:
        raise ValueError("Invalid primes")
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = modinv(e, phi)
    return (e, n), (d, n)


def save_keys(public_keys, private_keys):
    with open(os.path.join(Path, "public_keys.txt"), "w") as f:
        for e, n in public_keys:
            f.write(f"{e},{n}\n")
    with open(os.path.join(Path, "private_keys.txt"), "w") as f:
        json.dump(private_keys, f)


if __name__ == "__main__":
    pq_list = [(10000019, 10000103), (10000000019,
                                      10000000583), (10093, 1000000000169)]
    public_keys, private_keys = [], []
    for p, q in pq_list:
        pub, priv = generate_keypair(p, q)
        public_keys.append(pub)
        private_keys.append(priv)
        save_keys(public_keys, private_keys)

    print("\nPublic Keys:")
    for i, (e, n) in enumerate(public_keys):
        print(f"Key {i+1}: e = {e}, n = {n}")
