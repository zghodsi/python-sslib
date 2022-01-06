from sslib import shamir
from sslib import util
import secrets
import base64

mysecret = secrets.token_bytes(100)
verifiable = False
#mysecret = b'\xfb'

#secret_length = 3
#largest_representable_secret = util.int_from_bytes(bytes([255]) * secret_length)
#prime = util.select_prime_larger_than(largest_representable_secret)
#print("q = ", prime)

required_shares = 3
distributed_shares = 10
#shamirSecret = shamir.to_base64(shamir.split_secret("this is my secret".encode('ascii'), required_shares, distributed_shares))
shamirSecret = shamir.split_secret(mysecret, required_shares, distributed_shares, verifiable=verifiable)
shamirSecretb64 = shamir.to_base64(shamirSecret)
print(shamirSecretb64)

if verifiable:
    for i in range(distributed_shares):
        shamir.feldman_verification(shamirSecret['prime2'], shamirSecret['generator'], \
            shamirSecret['shares'][i][0], shamirSecret['shares'][i][1], shamirSecret['commits'])

#Secret = shamir.recover_secret(shamir.from_base64(shamirSecret)).decode('ascii')
Secret = shamir.recover_secret(shamir.from_base64(shamirSecretb64))
print (Secret==mysecret)
