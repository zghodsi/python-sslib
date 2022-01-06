from .. import util
from .. import randomness
import warnings
import base64
import binascii
import gmpy2

class Polynomial:
    def __init__(self, prime_mod, coefficients):
        # coefficients = [a_k, ..., a_1, a_0] where P(x) = a_k*x^k + ... + a_1*x + a_0
        if not isinstance(prime_mod, int):
            raise TypeError("prime mod must be an int")
        if prime_mod <= 1:
            raise ValueError("invalid prime mod")
        if len(coefficients) >= prime_mod:
            raise ValueError("prime mod must exceed number of coefficients")
        for coefficient in coefficients:
            if not isinstance(coefficient, int):
                raise TypeError("coefficients must be ints")
        for coefficient in coefficients:
            if coefficient < 0 or coefficient >= prime_mod:
                raise ValueError("out-of-range coefficients")
        self.prime_mod = prime_mod
        self.coefficients = coefficients
    def evaluate(self, x):
        if not isinstance(x, int):
            raise TypeError("x-coordinate must be an int")
        if x < 0 or x >= self.prime_mod:
            raise ValueError("out-of-range x-coordinate")
        if x == 0:
            raise ValueError("P(0) may not be given, as it corresponds to the secret")
        y = 0
        for coefficient in self.coefficients:
            y *= x
            y %= self.prime_mod
            y += coefficient
            y %= self.prime_mod
        return y

def lagrange_interpolation(x, points, prime_mod):
    # points = [(x0, y0), (x1, y1), ...]
    if prime_mod <= 1:
        raise ValueError("invalid prime mod")
    if x < 0 or x >= prime_mod:
        raise ValueError("out-of-range value")
    for (xi, yi) in points:
        if xi < 0 or xi >= prime_mod or yi < 0 or yi >= prime_mod:
            raise ValueError("invalid points")
    y = 0
    for i, (xi, yi) in enumerate(points):
        numerator = yi
        denominator = 1
        for j, (xj, yj) in enumerate(points):
            if j == i:
                continue
            numerator *= (x - xj + prime_mod) % prime_mod
            numerator %= prime_mod
            denominator *= (xi - xj + prime_mod) % prime_mod
            denominator %= prime_mod
        y += (numerator*util.modular_inverse(denominator, prime_mod)) % prime_mod
        y %= prime_mod
    return y

def split_secret(secret_bytes, required_shares, distributed_shares, verifiable=False, **kwargs):
    if required_shares > distributed_shares:
        raise ValueError("distributed_shares must be greater than or equal to required_shares")
    secret_bytes = bytes([42]) + secret_bytes
    secret_length = len(secret_bytes)
    largest_representable_secret = util.int_from_bytes(bytes([255]) * secret_length)
    prime2 = 0
    generator = 0
    if verifiable:
        prime_mod, prime2, generator = util.select_prime_feldman(largest_representable_secret)
    else:
        prime_mod = kwargs.get('prime_mod', util.select_prime_larger_than(largest_representable_secret))
    if largest_representable_secret >= prime_mod:
        raise ValueError("prime mod is not large enough")
    prime_bytes = util.required_bytes_given_value(prime_mod-1)
    with kwargs.get('randomness_source', randomness.RandomReader() if secret_length <= 65
            else randomness.UrandomReader()) as randomness_source:
        secret = util.int_from_bytes(secret_bytes)
        coefficients = []
        for i in range(1, required_shares):
            coefficients.append(util.int_from_bytes(randomness_source.next_bytes(prime_bytes)) % prime_mod)
        coefficients.append(secret)
        polynomial = Polynomial(prime_mod, coefficients)
        shares = []
        for i in range(1, distributed_shares+1):
            shares.append((i, util.int_to_bytes(polynomial.evaluate(i))))
        commits = []
        if verifiable:
            for i in range(0, required_shares):
#                commits.append(generator**coefficients[i] % prime2)
                commits.append(util.int_to_bytes(int(gmpy2.powmod(gmpy2.mpz(generator),
                    gmpy2.mpz(coefficients[i]), gmpy2.mpz(prime2)))))
        return {
            'required_shares': required_shares,
            'prime_mod': util.int_to_bytes(prime_mod),
            'prime2' : util.int_to_bytes(prime2),
            'generator' : util.int_to_bytes(generator),
            'shares': shares,
            'commits': commits,
        }


def feldman_verification(prime2, generator, index, share, commits):
    if len(commits)==0:
        raise ValueError("commits where not generated, did you set the verifiable flag?")
    prime2 = util.int_from_bytes(prime2)
    generator = util.int_from_bytes(generator)
    share = util.int_from_bytes(share)

    #val1 = generator**share % prime2
    val1 = gmpy2.powmod(gmpy2.mpz(generator), gmpy2.mpz(share), gmpy2.mpz(prime2))

    val2=1
    for j in range(len(commits)):
        #val2 *= commits[len(commits)-j-1]**(index**j) % prime2
        val2 *= gmpy2.powmod(gmpy2.mpz(util.int_from_bytes(commits[len(commits)-j-1])),
                gmpy2.mpz(index**j),  gmpy2.mpz(prime2))
    val2 = val2 % prime2

    if val1 != val2:
        print ("val1={}, val2={}".format(val1, val2))
        raise ValueError("Feldman verification failed")


def recover_secret(data):
    shares = data.get('shares')
    if not shares:
        raise ValueError("shares must be provided")
    required_shares = data.get('required_shares')
    if required_shares:
        if len(shares) < required_shares:
            raise ValueError("not enough shares have been provided")
        shares = shares[0:required_shares]
    else:
        warnings.warn("The number of required shares has not been specified. If not enough shares are provided, an incorrect secret will be produced without detection.")
    prime_mod = data.get('prime_mod')
    if prime_mod is None:
        raise ValueError("prime mod must be provided")
    if isinstance(prime_mod, bytes):
        prime_mod = util.int_from_bytes(prime_mod)
    if not isinstance(prime_mod, int):
        raise TypeError("invalid prime mod")
    if prime_mod <= 1:
        raise ValueError("invalid prime mod")
    points = []
    for x, y in shares:
        if not isinstance(x, int):
            raise TypeError("the first entry of each a share must be an int")
        if not isinstance(y, bytes):
            raise TypeError("the second entry of each a share must be an array of bytes")
        points.append((x, util.int_from_bytes(y)))
    return util.int_to_bytes(lagrange_interpolation(0, points, prime_mod))[1:]

def to_base64(data):
    encode_share = lambda xy: str(xy[0]) + "-" + base64.b64encode(xy[1]).decode('ascii')
    encode_commit = lambda x: base64.b64encode(x).decode('ascii')
    return {
        'required_shares': data['required_shares'],
        'prime_mod': base64.b64encode(data['prime_mod']).decode('ascii'),
        'prime2': base64.b64encode(data['prime2']).decode('ascii'),
        'generator': base64.b64encode(data['generator']).decode('ascii'),
        'shares': list(map(encode_share, data['shares'])),
        'commits': list(map(encode_commit, data['commits']))
    }

def from_base64(data):
    decode_tuple = lambda xy: (int(xy[0]), base64.b64decode(xy[1]))
    decode_share = lambda s: decode_tuple(tuple(s.split("-")))
    decode_commit = lambda x: base64.b64decode(x)
    return {
        'required_shares': data['required_shares'],
        'prime_mod': data['prime_mod'] if isinstance(data['prime_mod'], int)
                else base64.b64decode(data['prime_mod']),
        'prime2': data['prime2'] if isinstance(data['prime2'], int)
                else base64.b64decode(data['prime2']),
        'generator': data['generator'] if isinstance(data['generator'], int)
                else base64.b64decode(data['generator']),
        'shares': list(map(decode_share, data['shares'])),
        'commits': list(map(decode_commit, data['commits']))
    }

def to_hex(data):
    encode_share = lambda xy: str(xy[0]) + "-" + binascii.hexlify(xy[1]).decode('ascii')
    encode_commit = lambda x: binascii.hexlify(x).decode('ascii')
    return {
        'required_shares': data['required_shares'],
        'prime_mod': binascii.hexlify(data['prime_mod']).decode('ascii'),
        'shares': list(map(encode_share, data['shares'])),
        'commits': list(map(encode_commit, data['commits']))
    }

def from_hex(data):
    decode_tuple = lambda xy: (int(xy[0]), binascii.unhexlify(xy[1]))
    decode_share = lambda s: decode_tuple(tuple(s.split("-")))
    decode_commit = lambda x: binascii.unhexlify(x)
    return {
        'required_shares': data['required_shares'],
        'prime_mod': data['prime_mod'] if isinstance(data['prime_mod'], int)
                else binascii.unhexlify(data['prime_mod']),
        'shares': list(map(decode_share, data['shares'])),
        'commits': list(map(decode_commit, data['commits']))
    }
