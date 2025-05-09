import os
import json
from ast import literal_eval

Path = " "

def recover_original_from_inserted(s):
    return ''.join(s[i:i+2] for i in range(0, len(s), 3))

def decrypt(private_keys, ciphertext, block_size):
    plaintext = ""
    for i, c in enumerate(ciphertext):
        d, n = private_keys[i % len(private_keys)]
        num = pow(c, d, n)
        block_str = str(num).zfill(3 * block_size)
        chars = [chr(int(block_str[i:i+3])) for i in range(0, len(block_str), 3)]
        plaintext += ''.join(chars)
    return recover_original_from_inserted(plaintext)

def load_private_keys():
    with open(os.path.join(Path, "private_keys.txt")) as f:
        return [tuple(map(int, pair)) for pair in json.load(f)]

if __name__ == "__main__":
    ciphertext_path = os.path.join(Path, "ciphertext.txt")

    if not os.path.exists(ciphertext_path):
        print("ciphertext.txt not found.")
    else:
        private_keys = load_private_keys()
        with open(ciphertext_path, "r") as f:
            block_size = int(f.readline())
            ciphertext = literal_eval(f.readline())

        print("Decrypted message:")
        print(decrypt(private_keys, ciphertext, block_size))
