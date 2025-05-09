import random

def is_prime(n):
    """Check if a number is prime."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    w = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += w
        w = 6 - w
    return True

def generate_prime_candidate(length):
    """Generate a random odd integer of a specified length."""
    prime_candidate = random.getrandbits(length)
    prime_candidate |= (1 << length - 1) | 1  # Set the highest and lowest bits
    return prime_candidate

def generate_prime_number(length=512):
    """Generate a prime number of a specified length."""
    prime_candidate = 4
    while not is_prime(prime_candidate):
        prime_candidate = generate_prime_candidate(length)
    return prime_candidate

def gcd(a, b):
    """Compute the greatest common divisor of a and b."""
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """Compute the modular inverse of a modulo m."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None  # Modular inverse does not exist
    else:
        return x % m

def extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def generate_rsa_keypair(key_length=512):
    """Generate RSA key pair."""
    p = generate_prime_number(key_length // 2)
    q = generate_prime_number(key_length // 2)
    N = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = mod_inverse(e, phi)
    return ((N, e), (N, d))

def encrypt_rsa(public_key, plaintext):
    """Encrypt plaintext using RSA."""
    N, e = public_key
    # Convert plaintext to integer
    message = int.from_bytes(plaintext.encode(), 'big')
    if message >= N:
        raise ValueError("Plaintext too large for RSA modulus.")
    ciphertext = pow(message, e, N)
    return ciphertext

def decrypt_rsa(private_key, ciphertext):
    """Decrypt ciphertext using RSA."""
    N, d = private_key
    message = pow(ciphertext, d, N)
    # Convert integer back to bytes
    plaintext = message.to_bytes((message.bit_length() + 7) // 8, 'big').decode()
    return plaintext

# Example usage
if __name__ == "__main__":
    # Generate RSA key pair
    public_key, private_key = generate_rsa_keypair(key_length=1024)
    print("Public Key:", public_key)
    print("Private Key:", private_key)

    # Example plaintext
    plaintext = "Hello, RSA!"
    print("Plaintext:", plaintext)

    # Encrypt
    ciphertext = encrypt_rsa(public_key, plaintext)
    print("Ciphertext:", ciphertext)

    # Decrypt
    decrypted_text = decrypt_rsa(private_key, ciphertext)
    print("Decrypted Text:", decrypted_text)