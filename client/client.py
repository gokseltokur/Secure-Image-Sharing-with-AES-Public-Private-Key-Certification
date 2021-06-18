import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sys
import logging
import tqdm
import os
from Crypto.Random import get_random_bytes
from Crypto import Random
from Crypto.Cipher import AES
import io
import PIL.Image
import os
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509


def create_public_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    store_private_key(private_key)
    store_public_key(public_key)

    return public_key, private_key


def store_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key.pem', 'wb') as f:
        f.write(pem)


def store_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key.pem', 'wb') as f:
        f.write(pem)


def send_file(s, filename, filesize):
    progress = tqdm.tqdm(range(
        filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "rb") as f:
        while True:
            # read the bytes from the file
            bytes_read = f.read(2048)
            if not bytes_read:
                # file transmitting is done
                s.sendall(b'@@DONE')
                break
            # we use sendall to assure transimission in
            # busy networks
            s.sendall(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))


def receive_file(client_socket, filename, filesize):
    progress = tqdm.tqdm(range(
        filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "wb") as f:
        while True:
            # read 1024 bytes from the socket (receive)
            bytes_read = client_socket.recv(2048)
            if bytes_read == b'@@DONE':
                # nothing is received
                # file transmitting is done
                break
            if not bytes_read:
                # nothing is received
                # file transmitting is done
                break
            # write to the file the bytes we just received
            f.write(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))


def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)


def encrypt_image(key, iv, file):

    cwd = os.getcwd()
    input_file = open(cwd + "/" + file, "rb")
    input_data = input_file.read()
    input_file.close()
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    enc_data = cbc_cipher.encrypt(pad(input_data))
    enc_file = open(os.path.join(cwd + "/common/", file)+".enc", "wb")
    enc_file.write(enc_data)
    enc_file.close()

    return enc_data


def decrypt_image(key, iv, enc_data):
    cwd = os.getcwd()
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_data = cbc_cipher.decrypt(pad(enc_data))

    imageStream = io.BytesIO(plain_data)
    imageFile = PIL.Image.open(imageStream)
    file_str = file.lower()
    if(".jpg" in file_str):
        imageFile.save(((os.path.join(cwd + "/common", file))[:-8])+".JPG")
    elif(".png" in file_str):
        imageFile.save(((os.path.join(cwd + "/common", file))[:-8]) + ".png")


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


def send_image():
    key = get_random_bytes(16)
    iv = Random.new().read(AES.block_size)

    encrypted_img = encrypt_image(key, iv, "kyle.png")

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        return public_key


def verify_certificate(certificate_file):
    server_public_key = load_public_key('server_public_key.pem')
    user_public_key = load_public_key('public_key.pem').public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print('user_public_key', user_public_key)

    with open(certificate_file) as s:
        certificate = s.read()
        decoded_certificate = base64.b64decode(certificate)
        try:
            server_public_key.verify(
                decoded_certificate,
                user_public_key,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            print('Valid Certificate')
            #sys.exit(0)
        except InvalidSignature:
            print('Invalid Certificate!')
            #sys.exit(1)


# create an ipv4 (AF_INET) socket object using the tcp protocol (SOCK_STREAM)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect the client
# client.connect((target, port))
client.connect(('127.0.0.1', 1233))
response = client.recv(2048)
# Input UserName
name = input(response.decode())
client.send(str.encode(name))
response = client.recv(2048)
# Input Password
password = input(response.decode())
client.send(str.encode(password))
''' Response : Status of Connection :
	1 : Registeration successful 
	2 : Connection Successful
	3 : Login Failed
'''


# Input Public Key
public_key, _ = create_public_private_key()

# Send public key of client
filesize = os.path.getsize('public_key.pem')
client.send(str.encode(str(filesize)))
send_file(client, 'public_key.pem', filesize)

# Receive Certificate from server
certificate_filesize = client.recv(2048)
certificate_filesize = certificate_filesize.decode()
certificate_filesize = int(certificate_filesize)
receive_file(client, 'certificate.CA', certificate_filesize)

# Receive Public Key of the server
filesize = int(client.recv(2048).decode())
receive_file(client, 'server_public_key.pem', filesize)


verify_certificate('certificate.CA')


# Receive response
response = client.recv(2048)
response = response.decode()
print(response)


client.close()
