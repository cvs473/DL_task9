from Crypto.Util import number
import decimal
import math

def randSafePrime(a, b):
    while True:
        bsize = number.getRandomRange(a, b)
        q = number.getPrime(bsize)
        if number.isPrime(2*q + 1) == True:
            return (2*q + 1)
        else:
            continue

def findPrimeFactors(n):
    factors = set()
    while (n % 2 == 0):
        factors.add(2)
        n //= 2
    for i in range(3, int(decimal.Decimal(n).sqrt()), 2):
        while (n % i == 0):
            factors.add(i)
            n //= i
    if (n > 2):
        factors.add(n)
    return factors

def primitiveRoot(p):
    # assuming p is safe prime
    while True: 
        g = number.getRandomRange(1, p-1)
        if (g ** 2) % p == 1:
            continue
        if pow(g, (p-1)//2, p) == 1:
            continue
        return g 

def keyGen(g, p):
    a = number.getRandomRange(1, p-1)
    b = pow(g, a, p)
    return a, b

def digital_sign(og_message, a, p, g):
    while True:
        k = number.getRandomRange(1, p-1)
        if math.gcd(k, p-1) != 1:
            continue
        else:
            break
    r = pow(g, k, p)
    m = abs(hash(og_message))
    k_inv = pow(k, -1, p-1)
    s = ((m - a * r) * k_inv) % (p - 1)
    return r, s

def verify_auth(og_message, r, s, b, p, g):
    m = abs(hash(og_message))
    v = (pow(r, s, p) * pow(b, r, p)) % p
    return pow(g, m, p) == v 

def encrypt(msg, b, g, p):
    t = ''
    for c in msg:
        t += '{0:b}'.format(ord(c))

    while len(t) % 7 != 0:
        t = '0' + t
    m = int(t, 2)
    k = number.getRandomRange(1, p-1)
    x = pow(g, k, p)
    y = (pow(b, k, p) * (m % p)) % p
    return x, y

def decrypt(x, y, a, p):
    msg = '' 
    s = pow(x, a, p)
    s_inv = pow(s, -1, p)
    m = (y * s_inv) % p
    bin_str = bin(m).lstrip('0b')
    while len(bin_str) % 7 != 0:
        bin_str = '0' + bin_str
    for i in range(0, len(bin_str), 7):
        t = bin_str[i:i+7]
        dig = int(t, 2)
        msg += chr(dig)
    return msg
