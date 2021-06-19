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
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
import json
import ast
import simplejson


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
    total = 0
    with open(filename, "rb") as f:
        # progress or tqdm bar
        for _ in progress:
            while total != filesize:
                # read the bytes from the file
                bytes_read = f.read(2048)

                # to check when file is done transmitting
                if total == filesize:
                    break

                # we use sendall to assure transimission in
                # busy networks
                s.sendall(bytes_read)

                # update the progress bar
                progress.update(len(bytes_read))
                total += len(bytes_read)
    f.close()


def receive_file(client_socket, filename, filesize):
    progress = tqdm.tqdm(range(
        filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    total = 0
    with open(filename, "wb") as f:
        for _ in progress:
            while total != filesize:
                # read 1024 bytes from the socket (receive)
                bytes_read = client_socket.recv(2048)

                if total == filesize:
                    # nothing is received
                    # file transmitting is done
                    break
                # write to the file the bytes we just received
                f.write(bytes_read)

                # update the progress bar
                progress.update(len(bytes_read))
                total += len(bytes_read)
    f.close()


def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)


def encrypt_image(key, iv, file):

    cwd = os.getcwd()
    print("cwd in encrypt image: " + cwd)
    input_file = open(cwd + "/" + file, "rb")
    input_data = input_file.read()
    input_file.close()
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    enc_data = cbc_cipher.encrypt(pad(input_data))
    enc_file = open(os.path.join(cwd, file)+".enc", "wb")
    enc_file.write(enc_data)
    enc_file.close()

    return enc_data


def decrypt_image(key, iv, enc_data, filename):
    cwd = os.getcwd()
    print("cwd in decrypt image: " + cwd)
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_data = cbc_cipher.decrypt(pad(enc_data))

    imageStream = io.BytesIO(plain_data)
    imageFile = PIL.Image.open(imageStream)
    file_str = filename.lower()
    if(".jpg" in file_str):
        imageFile.save(((os.path.join(cwd, filename))[:-8])+".JPG")
    elif(".png" in file_str):
        imageFile.save(((os.path.join(cwd, filename))[:-8]) + ".png")


def sign(message, private_key):
    return private_key.sign(message, padding.PSS(mgf=padding.MGF1(
        hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())


def verify(message, signature, public_key):
    return public_key.verify(
        message,
        signature,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())


def encrypt_with_rsa_public_key(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)


def decrypt_message_with_private_key(private_key, encrypted):
    decipher = PKCS1_OAEP.new(private_key)
    return decipher.decrypt(encrypted)


def send_image(socket, private_key, public_key):
    filename = "kyle.png"
    # generate key and iv
    key = get_random_bytes(16)
    iv = Random.new().read(AES.block_size)

    encrypted_img = encrypt_image(key, iv, filename)

    digital_sign = b64encode(sign(encrypted_img, private_key))

    # TODO implement public key enryption
    encrypted_key = encrypt_with_rsa_public_key(public_key, key)
    encrypted_iv = encrypt_with_rsa_public_key(public_key, iv)

    # m = {"type": "POST_IMAGE", "encrypted_img": encrypted_img, "digital_sign": digital_sign,
    #      "encrypted_key": encrypted_key, "encrypted_iv": encrypted_iv}

    m = "POST_IMAGE\n\n" + str(encrypted_img) + '\n\n' + str(digital_sign) + \
        '\n\n' + str(encrypted_key) + '\n\n' + str(encrypted_iv)
    # print(m)
    # data = json.dumps(m)

    with open(filename + '.txt', 'w') as outfile:
        outfile.write(m)
    outfile.close()

    socket.send(b"POST_IMAGE")

    filesize = os.path.getsize('data.txt')

    socket.send(str.encode(str(filesize)))
    socket.send(filename.encode())

    send_file(socket, 'data.txt', filesize)


def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        return public_key


def verify_certificate(certificate_file):
    server_public_key = load_public_key('server_public_key.pem')
    user_public_key = load_public_key('public_key.pem').public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
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
            # sys.exit(0)
        except InvalidSignature:
            print('Invalid Certificate!')
            # sys.exit(1)


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
public_key, private_key = create_public_private_key()

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

if response == "Registration Successful":
    print("girdi")
    f = open('server_public_key.pem', 'r')
    server_public_key = RSA.importKey(f.read())
    f.close()

    send_image(client, private_key, server_public_key)


client.close()
