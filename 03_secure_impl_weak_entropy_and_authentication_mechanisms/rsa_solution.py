import sys
import Crypto.Util.number
from Crypto.Util.number import getPrime, GCD, inverse

def encrypt(m, e, N):
	return pow(m, e, N)

def decrypt(c, d, N):
    r = 1
    x = c % N
    while d > 0:
        if d & 1:
            r = (r * x) % N
        x = (x * x) % N
        d >>= 1
    return r

def ct_decrypt(c, d, N):
    r = 1
    for i in range(N.bit_length() - 1, -1, -1):
        r = (r * r) % N

        bit = (d >> i) & 1
        mul = (r * c) % N

        # Constant-time select:
        # if bit == 1 → y = mul
        # if bit == 0 → y = y
        r = (mul * bit + r * (1 - bit)) % N

    return r

def ct_monty(c, d, N):
    r0 = 1
    r1 = c % N

    for i in range(N.bit_length() - 1, -1, -1):
        bit = (d >> i) & 1

        # Conditional swap (branchless)
        swap = bit
        r0, r1 = (
            r0 * (1 - swap) + r1 * swap,
            r1 * (1 - swap) + r0 * swap,
        )

        r1 = (r0 * r1) % N
        r0 = (r0 * r0) % N

        # Swap back
        r0, r1 = (
            r0 * (1 - swap) + r1 * swap,
            r1 * (1 - swap) + r0 * swap,
        )

    return r0

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


if __name__ == '__main__':
    if (len(sys.argv) < 3):
        print(f'usage: {sys.argv[0]} <bits> <message>', file=sys.stderr)
        exit(1)
    main(int(sys.argv[1]), sys.argv[2])
