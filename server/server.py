import socket
import os
import tqdm
import threading
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sys
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64



logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s',
                    filename='server/server.log', filemode='w')


# Create Socket (TCP) Connection
ServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
host = '127.0.0.1'
port = 1233
ThreadCount = 0
try:
    ServerSocket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waiting for a Connection..')
ServerSocket.listen(5)
HashTable = {}


def sign_certificate(public_key, username):
    with open("server/server_private_key.pem", "rb") as key_file:
        server_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        #message = b'encrypt me!'
        #public_key = ... # Use one of the methods above to get your public key
        public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        certificate = server_private_key.sign(public_key, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        print(base64.b64encode(certificate))
        with open('server/certificates/certificate_' + str(username) + '.CA', 'wb') as f:
            f.write(base64.b64encode(certificate))


def create_server_public_private_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
    public_key = private_key.public_key()
    store_server_private_key(private_key)
    store_server_public_key(public_key)

    return public_key, private_key


def store_server_private_key(private_key):
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

    with open('server/server_private_key.pem', 'wb') as f:
        f.write(pem)


def store_server_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('server/server_public_key.pem', 'wb') as f:
        f.write(pem)

def store_public_key(public_key, username):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('server/public_keys/public_key' + str(username) + '.pem', 'wb') as f:
        f.write(pem)


def receive_file(client_socket, filename, filesize):
    progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    print('@@@')
    with open(filename, "wb") as f:
        while True:
            print('@@@')
            # read 1024 bytes from the socket (receive)
            bytes_read = client_socket.recv(2048)
            if not bytes_read:
                # nothing is received
                # file transmitting is done
                break
            # write to the file the bytes we just received
            f.write(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))
    print('@@@DONE')


def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        return public_key

# Function : For each client


def send_file(s, filename, filesize):
    progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)

    with open(filename, "rb") as f:
        while True:
            # read the bytes from the file
            bytes_read = f.read(2048)
            if not bytes_read:
                # file transmitting is done
                break
            # we use sendall to assure transimission in
            # busy networks
            s.sendall(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))


def threaded_client(connection):
    connection.send(str.encode('ENTER USERNAME : '))  # Request Username
    name = connection.recv(2048)
    connection.send(str.encode('ENTER PASSWORD : '))  # Request Password
    password = connection.recv(2048)
    password = password.decode()
    name = name.decode()
    # Password hash using SHA256
    password = hashlib.sha256(str.encode(password)).hexdigest()


    # REGISTERATION PHASE
    # If new user,  regiter in Hashtable Dictionary
    if name not in HashTable:
        HashTable[name] = password
        print('Registered : ', name)
        print("{:<8} {:<20}".format('USER', 'PASSWORD'))
        for k, v in HashTable.items():
            label, num = k, v
            print("{:<8} {:<20}".format(label, num))
        print("-------------------------------------------")

        #store_public_key(user_public_key, name)
        logging.info("User's public key receiving")
        user_public_key_filesize = connection.recv(2048)
        user_public_key_filesize = user_public_key_filesize.decode()
        user_public_key_filesize = int(user_public_key_filesize)
        print("User's public key receiving")
        user_public_key_filename = 'server/public_keys/public_key_' + str(name) + '.pem'
        print('@@@')
        receive_file(connection, user_public_key_filename, user_public_key_filesize)
        user_public_key = load_public_key(user_public_key_filename)
        logging.info("User's public key received")
        print("User's public key received")

        # Sign Certificate and Send to the client
        logging.info("User's certificate will be created")
        print("User's certificate will be created")
        sign_certificate(user_public_key, name)
        user_certificate_filename = 'server/certificates/certificate_' + str(name) + '.CA'
        logging.info("User's certificate is created")
        print("User's certificate is created")
        logging.info("User's certificate will be sent")
        print("User's certificate will be sended")
        user_certificate_filesize = os.path.getsize(user_certificate_filename)
        connection.send(str.encode(str(user_certificate_filesize)))
        send_file(connection, user_certificate_filename, user_certificate_filesize)
        logging.info("User's certificate sent")
        print("User's certificate is sent")


        connection.send(str.encode('Registration Successful'))
        
        logging.info("Registeration Successful username: {} password: {} public_key: {}".format(
            name, password, 'server/public_keys/public_key_' + str(name) + '.pem'))
        
    # If already existing user, check if the entered password is correct
    else:

        if(HashTable[name] == password):
            # Response Code for Connected Client
            connection.send(str.encode('Connection Successful'))
            print('Connected : ', name)
        else:
            # Response code for login failed
            connection.send(str.encode('Login Failed'))
            print('Connection denied : ', name)
    while True:
        break
    connection.close()


create_server_public_private_key()

while True:
    Client, address = ServerSocket.accept()
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
    ThreadCount += 1
    print('Connection Request: ' + str(ThreadCount))
ServerSocket.close()
