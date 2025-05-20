# Discrete Math Cryptography

This repository contains implementations of various cryptographic algorithms and systems, focusing on RSA, Elliptic Curve Cryptography (ECC), and ElGamal encryption schemes. The implementations are designed for educational purposes and demonstrate fundamental concepts in discrete mathematics and cryptography.

## Implementations

### RSA Cryptography
The RSA implementation consists of three main components:

1. **Key Generation** (`rsa_generate_keys.py`)
   - Generates RSA key pairs using prime numbers
   - Supports multiple key sizes
   - Saves public and private keys to separate files
   ```python
   # Example usage
   from rsa_generate_keys import generate_keypair
   public_key, private_key = generate_keypair(p, q)  # p and q are prime numbers
   ```

2. **Encryption** (`rsa_encrypt.py`)
   - Encrypts messages using RSA public key
   - Handles message padding and encoding
   ```python
   # Example usage
   from rsa_encrypt import encrypt
   ciphertext = encrypt(message, public_key)
   ```

3. **Decryption** (`rsa_decrypt.py`)
   - Decrypts messages using RSA private key
   - Handles message unpadding and decoding
   ```python
   # Example usage
   from rsa_decrypt import decrypt
   plaintext = decrypt(ciphertext, private_key)
   ```

### Elliptic Curve Cryptography (ECC)
The ECC implementation (`ecc.py`) supports multiple NIST curves and provides:

- Key pair generation
- Encryption/Decryption using ECC
- Support for curves: P-192, P-224, P-256, P-384, P-521
```python
# Example usage
from ecc import generate_key_pair, ecc_encrypt, ecc_decrypt

# Generate keys
priv, pub = generate_key_pair(G, n, a, p)

# Encrypt
encrypted = ecc_encrypt(message, pub, G, n, a, p)

# Decrypt
decrypted = ecc_decrypt(encrypted, priv, a, p)
```

### ElGamal Cryptography
The ElGamal implementation (`elgamal.py`) provides:

- Key generation
- Encryption/Decryption
- Digital signatures
```python
# Example usage
from elgamal import generate_keys, encrypt, decrypt

# Generate keys
public_key, private_key = generate_keys()

# Encrypt
ciphertext = encrypt(message, public_key)

# Decrypt
plaintext = decrypt(ciphertext, private_key)
```

### Performance Comparison
The `comparison.py` script provides performance metrics and comparisons between different cryptographic implementations.

## Requirements

- Python 3.6+
- Required Python packages:
  - `hashlib`
  - `random`
  - `math`
  - `json`

## Usage

1. Clone the repository:
```bash
git clone https://github.com/yourusername/DiscreteMathCryptography.git
cd DiscreteMathCryptography
```

2. Generate RSA keys:
```bash
python rsa_generate_keys.py
```

3. Encrypt a message:
```bash
python rsa_encrypt.py
```

4. Decrypt a message:
```bash
python rsa_decrypt.py
```

5. Run ECC encryption/decryption:
```bash
python ecc.py
```

6. Run ElGamal encryption/decryption:
```bash
python elgamal.py
```

7. Compare performance:
```bash
python comparison.py
```
