import sys
import Crypto.Util.number
from Crypto.Util.number import getPrime, GCD, inverse

def encrypt(m, e, N):
	return pow(m, e, N)

# Right-to-left version
def decrypt(c, d, N):
    r = 1
    x = c % N
    while d > 0:
        if d & 1:
            r = (r * x) % N
        x = (x * x) % N
        d >>= 1
    return r

# Left-to-right version
def decrypt_ltor(c, d, N):
    r = 1
    for i in range(d.bit_length() - 1, -1, -1):
        r = (r * r) % N
        if (d >> i) & 1:
            r = (r * c) % N
    return r

def main(bits, message):
    # key generation
    while True:
        # sample two different primes
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p == q:
            continue
        N = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        # e needs to be invertible modulo phi(N)
        if GCD(e, phi) > 1:
            continue
        d = inverse(e,phi)

        print(f"Random Prime p = {p}")
        print(f"Random Prime q = {q}")
        print()
        print(f"Modulus N = {N}")
        print(f"Public exponent e = {e}")
        print(f"Private exponent d = {d}")
        break

    m = int.from_bytes(message.encode("utf-8"), "big") % N
    enc = encrypt(m, e, N)

    dec = decrypt(enc, d, N)

    plain = dec.to_bytes((N.bit_length() + 7) // 8, 'big')
    print()
    print(f"RSA ciphertext = {enc}")
    print(f"RSA plaintext = {plain.decode("utf-8")}")

    assert dec == m
    assert decrypt(enc, d, N) == decrypt_ltor(enc, d, N)

if __name__ == '__main__':
    if (len(sys.argv) < 3):
        print(f'usage: {sys.argv[0]} <bits> <message>', file=sys.stderr)
        exit(1)
    main(int(sys.argv[1]), sys.argv[2])
