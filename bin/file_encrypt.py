__author__ = 'goku'
import rsa

with open('public.pem') as handle:
    p = handle.read()
    public_key = rsa.PublicKey.load_pkcs1(p)

with open('private.pem') as handle:
    p = handle.read()
    private_key = rsa.PrivateKey.load_pkcs1(p)

crypto = rsa.encrypt('hello', public_key)
decrypt = rsa.decrypt(crypto, private_key)
print decrypt
