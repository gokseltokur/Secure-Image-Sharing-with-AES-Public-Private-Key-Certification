# Secure Image Sharing with AES Public Private Key Certification
## Group Members
* Göksel Tokur - 150116049
* Ertuğrul Sağdıç - 150116061
* Arda Bayram - 150116029

## <> This project is a simple image sharing system with several security features. <>
## 1. Registration and Public Key Certification

We created a local server running on port 1233. This server waits for clients to connect.
```python
ServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
host = '127.0.0.1'
port = 1233
```
Server and clients create their public and private keys with using 'cryptography' package the Python. Also, they store their keys to use again later. Private keys are stored in clients' and server's own spaces.
```python
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
```python
connection.send(str.encode('ENTER USERNAME : '))  # Request Username
name = connection.recv(2048)
connection.send(str.encode('ENTER PASSWORD : '))  # Request Password
password = connection.recv(2048)
```
The server has the password using SHA256.
```python
password = hashlib.sha256(str.encode(password)).hexdigest()
```

If the username is entered into the system for the first time, server save the new user and his/her password with using the hash table.
```python
HashTable[name] = password
```

After, registration is completed, server takes the client's public key and stores it in own local folder which is 'public_keys'.
```python
user_public_key_filesize = connection.recv(2048)
user_public_key_filesize = user_public_key_filesize.decode()
user_public_key_filesize = int(user_public_key_filesize)
user_public_key_filename = 'public_keys/public_key_' + str(name) + '.pem'
receive_file(connection, user_public_key_filename, user_public_key_filesize)
user_public_key = load_public_key(user_public_key_filename)
```

Server signs an individual certificate for each client and stores it in its own space.
```python
certificate = server_private_key.sign(public_key, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

with open('certificates/certificate_' + str(username) + '.CA', 'wb') as f:
    f.write(base64.b64encode(certificate))
```

Then, server sign the created certificate and send it to the user with together the server's public key.
```python
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
```python
connection.send(str.encode('Registration Successful'))
```

If the client has already registered to the server, server checks the entered password with the password in its hash table. If the passwords match, then the server accepts the client, denies vice versa.
```python
if(HashTable[name] == password):
    connection.send(str.encode('Connection Successful'))
else:
    connection.send(str.encode('Login Failed'))
```
## 2. Image Sharing

Finally, login or registration stages are completed, the server waits for the client's request. If the request is 'POST IMAGE', the server takes the image file from the user and stores it its own.
```python
while True:
    request = connection.recv(2048)

    if request == b'POST_IMAGE':
        filesize = int(connection.recv(2048).decode())
        filename = connection.recv(2048).decode()
        receive_file(connection, "images/" + filename + '.txt', filesize)
        send_notification(online_clients, "\nNEW_IMAGE " + filename)
```

Owner user of the image that will be sended to the server, first generates an AES key and encrypts the image with the AES key in CBC mode and randomly generated initialization vector. She also generates a digital signature of the image using her private key and SHA256 hash function. Then, she encrypts the AES key with the public key of the server. She sends POST_IMAGE command along with the these encrypted image, her digital signature and encrypted ARES key with IV to the server. Server stores these together with the name of the owner.
```python
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

    return enc_data, input_data

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

    encrypted_img, image = encrypt_image(key, iv, filename)

    digital_sign = b64encode(sign(image, private_key))

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

    filesize = os.path.getsize(filename + '.txt')

    socket.send(str.encode(str(filesize)))
    socket.send(filename.encode())

    send_file(socket, filename + '.txt', filesize)
```
## 3. Notification

When the image is received by server. Server sends notification that is "NEW_IMAGE image_name", to all online clients that is already connected.
```python
def send_notification(online_clients, notification):
    notification = str.encode(notification)
    for client in online_clients:
        print("@", client)
        client.send(notification)
```
```python
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
```
# Example screen captures:

## 1) An example demo :
   
![GitHub Logo](/ss/demo.png)


## 4. Image Download
After receiving the NEW_IMAGE message, a user can download
the image by sending a “DOWNLOAD image_name” message to the server. When
server receives this message, it sends the encrypted image, digital signature,
certificated public key of the owner, and the AES key encrypted with the public key of
requesting user.
```python
if splitted_response[0] == b"NEW_IMAGE":
    print('girdi')
    client.send(b"DOWNLOAD " + splitted_response[1])

    filesize = int(client.recv(2048).decode())
    receive_file(client, 'downloads/' + splitted_response[1].decode() + '.txt', filesize)

    verify_image(splitted_response[1].decode())
```
## 5. Decryption and Verification
After receiving these, user first extracts the AES key.
Next, she decrypts the image. Then, she checks the integrity and authentication of the
image by verifying the digital signature.
```python
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
```
```python
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
    
```
* Below parts is not fully completed.
  * Decrypt certificate
  * Verify image
```python
def verify_image(filename):
    with open("downloads/" + filename + '.txt', "rb") as image_file:
        data = image_file.read()

    splitted_data = data.split(b'\n\n')

    # image encrypted with aes key
    enrypted_img = splitted_data[0]
    # digital signature created with private key of the client
    digital_signature = splitted_data[1]
    certificate = splitted_data[2]
    # aes key and iv encrypted with public key of the server
    encrypted_key = splitted_data[3]
    encrypted_iv = splitted_data[4]

    f = open('private_key.pem', 'r')
    private_key = RSA.importKey(f.read())

    key = decrypt_message_with_private_key(private_key, b64decode(encrypted_key))
    iv = decrypt_message_with_private_key(private_key, b64decode(encrypted_iv))

    decrypted_img = decrypt_image(key, iv, b64decode(enrypted_img), filename)

    # save_image(decrypted_img, filename)

    # f = open('server_public_key.pem', 'r')
    # server_public_key = RSA.importKey(f.read())

    # return verify(decrypted_img, digital_signature, server_public_key)
```