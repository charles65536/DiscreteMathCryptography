import random
import time

# ================== 工具函数 ==================
def is_prime(n, k=20):
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

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = extended_gcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, _ = extended_gcd(a, m)
    return x % m if g == 1 else None

# ================== RSA 实现 ==================
class RSA:
    @staticmethod
    def generate_keys(bits):
        start = time.perf_counter()
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while p == q:
            q = generate_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = modinv(e, phi)
        end = time.perf_counter()
        return {'public': (e, n), 'private': (d, n), 'time': (end - start) * 1000}

    @staticmethod
    def encrypt(m, public_key):
        e, n = public_key
        return pow(m, e, n)

    @staticmethod
    def decrypt(c, private_key):
        d, n = private_key
        return pow(c, d, n)

# ================== ElGamal 实现 ==================
class ElGamal:
    @staticmethod
    def generate_keys(bits):
        start = time.perf_counter()
        p = generate_prime(bits)
        g = ElGamal.find_generator(p)
        x = random.randint(2, p - 2)
        h = pow(g, x, p)
        end = time.perf_counter()
        return {'public': (p, g, h), 'private': (p, x), 'time': (end - start) * 1000}

    @staticmethod
    def find_generator(p):
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
    def encrypt(m, public_key):
        p, g, h = public_key
        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
        s = pow(h, k, p)
        c2 = (m * s) % p
        return (c1, c2)

    @staticmethod
    def decrypt(cipher, private_key):
        p, x = private_key
        c1, c2 = cipher
        s = pow(c1, x, p)
        s_inv = modinv(s, p)
        return (c2 * s_inv) % p

# ================== 性能测试 ==================
def test_performance():
    test_cases = [(512, 10), (1024, 5), (2048, 3)]
    results = []

    for bits, trials in test_cases:
        print(f"\n正在测试 {bits} 位密钥...")

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

def print_results(results):
    print("\n{:=^60}".format(" 性能测试结果 "))
    for res in results:
        bits = res['bits']
        print(f"\n{'-'*30}\n密钥长度: {bits}位\n{'-'*30}")
        print("{:<8} | {:<12} | {:<10} | {:<10}".format("算法", "密钥生成(ms)", "加密(ms)", "解密(ms)"))
        print("-"*50)
        print("RSA     | {:>11.3f} | {:>9.3f} | {:>9.3f}".format(
            res['rsa']['key_gen'], res['rsa']['enc'], res['rsa']['dec']))
        print("ElGamal | {:>11.3f} | {:>9.3f} | {:>9.3f}".format(
            res['elgamal']['key_gen'], res['elgamal']['enc'], res['elgamal']['dec']))

def print_conclusion(results):
    print("\n{:=^60}".format(" 实验结论 "))

    def safe_div(a, b):
        return a / b if b != 0 else float('inf')

    def format_ratio(r):
        return "无穷大" if r == float('inf') else "{:.1f}".format(r)

    key_ratios = [safe_div(res['elgamal']['key_gen'], res['rsa']['key_gen']) for res in results]
    enc_ratios = [safe_div(res['elgamal']['enc'], res['rsa']['enc']) for res in results]
    dec_ratios = [safe_div(res['elgamal']['dec'], res['rsa']['dec']) for res in results]

    print(f"""1. 密钥生成速度:
   - RSA比ElGamal快约 {format_ratio(sum(key_ratios)/len(key_ratios))} 倍（平均）

2. 加密速度:
   - RSA比ElGamal快约 {format_ratio(sum(enc_ratios)/len(enc_ratios))} 倍（平均）

3. 解密速度:
   - RSA比ElGamal快约 {format_ratio(sum(dec_ratios)/len(dec_ratios))} 倍（平均）

注：测试样本量：512位10次，1024位5次，2048位3次
""")

# ================== 主程序入口 ==================
if __name__ == "__main__":
    results = test_performance()
    print_results(results)
    print_conclusion(results)
