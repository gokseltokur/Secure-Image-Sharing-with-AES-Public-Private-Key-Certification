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
from Crypto.Cipher import AES
import io
import PIL.Image
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s',
                    filename='server.log', filemode='w')


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
    with open("server_private_key.pem", "rb") as key_file:
        server_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        #message = b'encrypt me!'
        # public_key = ... # Use one of the methods above to get your public key
        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        certificate = server_private_key.sign(public_key, padding.PSS(mgf=padding.MGF1(
            hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        print(base64.b64encode(certificate))
        with open('certificates/certificate_' + str(username) + '.CA', 'wb') as f:
            f.write(base64.b64encode(certificate))
    key_file.close()


def create_server_public_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    public_key = private_key.public_key()
    store_server_private_key(private_key)
    store_server_public_key(public_key)

    return public_key, private_key


def store_server_private_key(private_key):
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

    with open('server_private_key.pem', 'wb') as f:
        f.write(pem)


def store_server_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('server_public_key.pem', 'wb') as f:
        f.write(pem)


def store_public_key(public_key, username):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_keys/public_key' + str(username) + '.pem', 'wb') as f:
        f.write(pem)


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


def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        return public_key


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
# Function : For each client

def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)

def decrypt_image(key, iv, enc_data, filename):
    cwd = os.getcwd()
    print("cwd in decrypt image: " + cwd)
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_data = cbc_cipher.decrypt(pad(enc_data))

    imageStream = io.BytesIO(plain_data)
    imageFile = PIL.Image.open(imageStream)
    imageFile.save(filename)


def encrypt_with_rsa_public_key(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)


def decrypt_message_with_private_key(private_key, encrypted):
    decipher = PKCS1_OAEP.new(private_key)
    return decipher.decrypt(encrypted)

def verify(message, signature, public_key):
    try:
        public_key.verify(message, signature, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print('Valid Signature')
        return True
    except InvalidSignature:
        print('Invalid Signature!')
        return False


def verify_image(filename, username):
    with open("images/" + filename + '.txt', "rb") as image_file:
        data = image_file.read()

    splitted_data = data.split(b'\n\n')

    # image encrypted with aes key
    enrypted_img = splitted_data[1]
    # digital signature created with private key of the client
    digital_signature = splitted_data[2]
    # aes key and iv encrypted with public key of the server
    encrypted_key = splitted_data[3]
    encrypted_iv = splitted_data[4]

    f = open('server_private_key.pem', 'r')
    server_private_key = RSA.importKey(f.read())

    key = decrypt_message_with_private_key(server_private_key, b64decode(encrypted_key))
    iv = decrypt_message_with_private_key(server_private_key, b64decode(encrypted_iv))

    decrypted_img = decrypt_image(key, iv, b64decode(enrypted_img), filename)

    f = open('public_keys/public_key_' + username + '.pem', 'r')
    user_public_key = RSA.importKey(f.read())

    return verify(decrypted_img, digital_signature, user_public_key)

def send_image(socket, requester_public_key, filename):
    with open("images/" + filename + '.txt', "rb") as image_file:
        data = image_file.read()

    splitted_data = data.split(b'\n\n')

    # image encrypted with aes key
    encrypted_img = splitted_data[1]
    # digital signature created with private key of the client
    digital_signature = splitted_data[2]
    # aes key and iv encrypted with public key of the server
    encrypted_key = splitted_data[3]
    encrypted_iv = splitted_data[4]
    sender_certificate = splitted_data[5]

    f = open('server_private_key.pem', 'r')
    server_private_key = RSA.importKey(f.read())

    key = decrypt_message_with_private_key(server_private_key, b64decode(encrypted_key))
    iv = decrypt_message_with_private_key(server_private_key, b64decode(encrypted_iv))

    requester_encrypted_key = encrypt_with_rsa_public_key(requester_public_key, key)
    requester_encrypted_iv = encrypt_with_rsa_public_key(requester_public_key, iv)

    m = b64encode(encrypted_img) + b'\n\n' + b64encode(digital_signature) + \
        b'\n\n' + sender_certificate + b'\n\n' + b64encode(requester_encrypted_key) + b'\n\n' + b64encode(requester_encrypted_iv)

    with open('send_files/' + filename + '.txt', 'wb') as outfile:
        outfile.write(m)
    outfile.close()

    filesize = os.path.getsize('send_files/' + filename + '.txt')

    socket.send(str.encode(str(filesize)))

    send_file(socket, 'send_files/' + filename + '.txt', filesize)
    

def threaded_client(connection):
    global online_clients
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
        user_public_key_filename = 'public_keys/public_key_' + \
            str(name) + '.pem'
        receive_file(connection, user_public_key_filename,
                     user_public_key_filesize)
        user_public_key = load_public_key(user_public_key_filename)
        logging.info("User's public key received")
        print("User's public key received")

        # Sign Certificate and Send to the client
        logging.info("User's certificate will be created")
        print("User's certificate will be created")
        sign_certificate(user_public_key, name)
        user_certificate_filename = 'certificates/certificate_' + \
            str(name) + '.CA'
        logging.info("User's certificate is created")
        print("User's certificate is created")
        logging.info("User's certificate will be sent")
        print("User's certificate will be sended")
        user_certificate_filesize = os.path.getsize(user_certificate_filename)
        connection.send(str.encode(str(user_certificate_filesize)))
        send_file(connection, user_certificate_filename,
                  user_certificate_filesize)
        logging.info("User's certificate sent")
        print("User's certificate is sent")

        logging.info("Server's public key will be sent")
        filesize = os.path.getsize('server_public_key.pem')
        connection.send(str.encode(str(filesize)))
        send_file(connection, 'server_public_key.pem', filesize)
        logging.info("Servers's public key sent to the user")

        connection.send(str.encode('Registration Successful'))

        logging.info("Registeration Successful username: {} password: {} public_key: {}".format(
            name, password, 'public_keys/public_key_' + str(name) + '.pem'))

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
        request = connection.recv(2048).decode()
        if request == 'POST_IMAGE':
            filesize = int(connection.recv(2048).decode())
            filename = connection.recv(2048).decode()
            receive_file(connection, "images/" + filename + '.txt', filesize)

            #verify_image(filename)
            send_notification(online_clients, "\nNEW_IMAGE " + filename)

        elif request.split()[0] == 'DOWNLOAD':
            print('girdi')
            image_name = request.split()[1]

            f = open('public_keys/public_key_' + str(name) + '.pem', 'r')
            requester_public_key = RSA.importKey(f.read())
            # socket, filename
            send_image(connection, requester_public_key, image_name)

    # connection.close()


def send_notification(online_clients, notification):
    notification = str.encode(notification)
    for client in online_clients:
        print("@", client)
        client.send(notification)


create_server_public_private_key()


online_clients = []
while True:
    Client, address = ServerSocket.accept()
    online_clients.append(Client)
    print('Online Clients = ', online_clients)
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
    ThreadCount += 1
    print('Connection Request: ' + str(ThreadCount))
ServerSocket.close()
