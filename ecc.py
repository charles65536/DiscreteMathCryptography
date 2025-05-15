import hashlib
import random
import time

# Various NIST curve parameters
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

def mod_inverse(a, m):
    return pow(a, m - 2, m)

def point_add(P, Q, a, p):
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

def scalar_multiply(k, P, a, p):
    R = (0, 0)
    while k:
        if k & 1:
            R = point_add(R, P, a, p)
        P = point_add(P, P, a, p)
        k >>= 1
    return R

def generate_key_pair(G, n, a, p):
    priv = random.randint(1, n - 1)
    pub = scalar_multiply(priv, G, a, p)
    return priv, pub

def derive_xor_key(shared_point, length):
    x_bytes = shared_point[0].to_bytes((shared_point[0].bit_length() + 7) // 8, 'big')
    hash_bytes = hashlib.sha256(x_bytes).digest()
    while len(hash_bytes) < length:
        hash_bytes += hashlib.sha256(hash_bytes).digest()
    return hash_bytes[:length]

def xor_data(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def ecc_encrypt(message: bytes, pubkey, G, n, a, p):
    ephemeral_priv, ephemeral_pub = generate_key_pair(G, n, a, p)
    shared_point = scalar_multiply(ephemeral_priv, pubkey, a, p)
    key = derive_xor_key(shared_point, len(message))
    ciphertext = xor_data(message, key)
    return {
        'ephemeral_pub': ephemeral_pub,
        'ciphertext': ciphertext
    }

def ecc_decrypt(bundle, privkey, a, p):
    ephemeral_pub = bundle['ephemeral_pub']
    ciphertext = bundle['ciphertext']
    shared_point = scalar_multiply(privkey, ephemeral_pub, a, p)
    key = derive_xor_key(shared_point, len(ciphertext))
    return xor_data(ciphertext, key)

if __name__ == "__main__":
    with open("input.txt", "rb") as f:
        plaintext = f.read()

    for name, params in curves.items():
        print(f"\nTesting Curve: {name}")
        p, a, b, G, n = params['p'], params['a'], params['b'], params['G'], params['n']

        # Key generation
        priv, pub = generate_key_pair(G, n, a, p)

        # Encryption
        t0 = time.time()
        enc = ecc_encrypt(plaintext, pub, G, n, a, p)
        t_enc = time.time() - t0

        # Decryption
        t1 = time.time()
        dec = ecc_decrypt(enc, priv, a, p)
        t_dec = time.time() - t1

        # Save decrypted result
        with open(f"decrypted_{name.replace('-', '')}.txt", "wb") as f:
            f.write(dec)

        print(f"Encryption time: {t_enc:.6f} seconds")
        print(f"Decryption time: {t_dec:.6f} seconds")
        #print(f"Decrypted content saved to decrypted_{name.replace('-', '')}.txt")
