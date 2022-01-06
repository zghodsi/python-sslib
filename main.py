from sslib import shamir
import secrets

mysecret = secrets.token_bytes(100)
verifiable = True

required_shares = 3
distributed_shares = 10
shamirSecret = shamir.split_secret(mysecret, required_shares, distributed_shares, verifiable=verifiable)
shamirSecretb64 = shamir.to_base64(shamirSecret)
print(shamirSecretb64)

if verifiable:
    for i in range(distributed_shares):
        shamir.feldman_verification(shamirSecret['prime2'], shamirSecret['generator'], \
            shamirSecret['shares'][i][0], shamirSecret['shares'][i][1], shamirSecret['commits'])

Secret = shamir.recover_secret(shamir.from_base64(shamirSecretb64))
print (Secret==mysecret)
