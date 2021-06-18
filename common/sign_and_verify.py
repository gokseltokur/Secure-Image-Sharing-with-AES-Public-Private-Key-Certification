from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode


def sign(message, private_key):
    signer = PKCS1_v1_5.new(private_key)
    digest = SHA256.new()
    digest.update(message.encode('utf-8'))
    return signer.sign(digest)


def verify(message, signature, public_key):
    signer = PKCS1_v1_5.new(public_key)
    digest = SHA256.new()
    digest.update(message.encode('utf-8'))
    return signer.verify(digest, signature)


def newkeys(keysize):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private


msg1 = "Hello Tony, I am Jarvis!"
keysize = 2048
(public, private) = newkeys(keysize)
signature = b64encode(sign(msg1, private))
verify = verify(msg1, b64decode(signature), public)

print("Signature: " + signature.decode('utf-8'))
print("Verify: %s" % verify)
