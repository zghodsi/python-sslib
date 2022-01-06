import random
import gmpy2

mersenne_primes = list(map(lambda x: 2**x-1, [
    17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423,
    9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091,
    # 756839, 859433, 1257787, 1398269, 2976221, 3021377, 6972593,
]))
extra_primes = [
    # smallest (n+1)-bit primes, where n is a power of two
    2**128 + 51,
    2**192 + 133, 
    2**256 + 297,
    2**320 + 27,
    2**384 + 231,
    2**448 + 211,
    2**512 + 75,
    2**768 + 183,
    2**1024 + 643,
    2**1536 + 75,
    2**2048 + 981,
    2**3072 + 813,
    2**4096 + 1761,
]

# Helper function
def isprime(n):
    return gmpy2.mpz(n).is_prime()

def get_params(q):
    r = 1
    while True:
        p = r*q + 1
        if isprime(p):
            break
        r = r + 1

    #print ("got r = ", r)

    # Compute elements of Z_p*
    # multiplicative group of integers mod p
    # integers coprime to p from {0,...,p-1}
    Z_p_star = []
    # pick i=2 to reduce computation
    for i in range(2, p):
        if(gmpy2.gcd(i,p) == 1):
            Z_p_star.append(i)
            break

    #print ("got z_p* = ", Z_p_star)

    # Z_p* is cyclic of order p-1, so it has exactly one subgroup
    # of order k for each divisor k of p-1
    # To obtain an element g of cyclic group G of prime order p, take
    # any element h of Z_p* and let g=h^r mod p where r=(p-1)/q
    # Compute elements of G = {h^r mod p | h in Z_p*}
    G = [] 
    for i in Z_p_star:
        G.append(i**r % p)


    G = list(set(G))
    G.sort()
    #print("got G = ", G)

    #if len(G)!=q:
    #    raise ValueError("Order of G must be equal to q.")

    # any element of G except 1 is a generator
    g = random.choice(list(filter(lambda g: g != 1, G)))
    return p, g



if __name__=="__main__":
    primes = sorted(mersenne_primes+extra_primes)
    q = 2**3072 + 813 
    p, g = get_params(q)
    print("q = {}, p = {}, g = {}".format(str(q), str(p) , str(g)))

