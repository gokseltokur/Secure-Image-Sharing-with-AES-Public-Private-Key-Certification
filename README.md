# Secure Image Sharing with AES Public Private Key Certification
## Group Members
* Göksel Tokur - 150116049
* Ertuğrul Sağdıç - 150116061
* Arda Bayram - 150116029

## <> This project is a simple image sharing system with several security features. <>
---------------------------------------------------------------------
## 1. Registration and Public Key Certification

We created a local server running on port 1233. This server waits for clients to connect.
```
ServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
host = '127.0.0.1'
port = 1233
```
Server and clients create their public and private keys with using 'cryptography' package the Python. Also, they store their keys to use again later. Private keys are stored in clients' and server's own spaces.
```
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
```

After a client is connected, the server asks USERNAME and PASSWORD to the client.
```
connection.send(str.encode('ENTER USERNAME : '))  # Request Username
name = connection.recv(2048)
connection.send(str.encode('ENTER PASSWORD : '))  # Request Password
password = connection.recv(2048)
```
The server has the password using SHA256.
```
password = hashlib.sha256(str.encode(password)).hexdigest()
```

If the username is entered into the system for the first time, server save the new user and his/her password with using the hash table.
```
HashTable[name] = password
```

After, registration is completed, server takes the client's public key and stores it in own local folder which is 'public_keys'.
```
user_public_key_filesize = connection.recv(2048)
user_public_key_filesize = user_public_key_filesize.decode()
user_public_key_filesize = int(user_public_key_filesize)
user_public_key_filename = 'public_keys/public_key_' + str(name) + '.pem'
receive_file(connection, user_public_key_filename, user_public_key_filesize)
user_public_key = load_public_key(user_public_key_filename)
```

Server signs an individual certificate for each client and stores it in its own space.
```
certificate = server_private_key.sign(public_key, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

with open('certificates/certificate_' + str(username) + '.CA', 'wb') as f:
    f.write(base64.b64encode(certificate))
```

Then, server sign the created certificate and send it to the user with together the server's public key.
```
sign_certificate(user_public_key, name)
user_certificate_filename = 'certificates/certificate_' + str(name) + '.CA'
user_certificate_filesize = os.path.getsize(user_certificate_filename)
connection.send(str.encode(str(user_certificate_filesize)))
send_file(connection, user_certificate_filename, user_certificate_filesize)

filesize = os.path.getsize('server_public_key.pem')
connection.send(str.encode(str(filesize)))
send_file(connection, 'server_public_key.pem', filesize)
```

After all the above steps are completed, server finishes the registration stage of the client as successful.
```
connection.send(str.encode('Registration Successful'))
```

If the client has already registered to the server, server checks the entered password with the password in its hash table. If the passwords match, then the server accepts the client, denies vice versa.
```
if(HashTable[name] == password):
    connection.send(str.encode('Connection Successful'))
else:
    connection.send(str.encode('Login Failed'))
```

Finally, login or registration stages are completed, the server waits for the client's request. If the request is 'POST IMAGE', the server takes the image file from the user and stores it its own.
```
while True:
    request = connection.recv(2048)

    if request == b'POST_IMAGE':
        filesize = int(connection.recv(2048).decode())
        filename = connection.recv(2048).decode()
        receive_file(connection, "images/" + filename + '.txt', filesize)
        send_notification(online_clients, "\nNEW_IMAGE " + filename)
```