from Crypto.Cipher import AES
import io
import PIL.Image
import os


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

    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_data = cbc_cipher.decrypt(pad(enc_data))

    imageStream = io.BytesIO(plain_data)
    imageFile = PIL.Image.open(imageStream)
    file_str = file.lower()
    if(".jpg" in file_str):
        imageFile.save(((os.path.join(cwd + "/common", file))[:-8])+".JPG")
    elif(".png" in file_str):
        imageFile.save(((os.path.join(cwd + "/common", file))[:-8]) + ".png")
