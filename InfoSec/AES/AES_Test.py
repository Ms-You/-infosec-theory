from Crypto.Cipher import AES
from Crypto import Random


def aesEncrypt(message, key, iv):
    cipher_Encrypt = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher_Encrypt.encrypt(message)
    return ciphertext


def aesDecrypt(encrypted, key, iv):
    cipher_Decrypt = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher_Decrypt.decrypt(encrypted)
    return plaintext


def main():
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    message = b'Information security and Programming, Test Message!!!'

    print('Message: ', message.decode())

    key = Random.new().read(KEY_SIZE)
    iv = Random.new().read(BLOCK_SIZE)

    print('AES Key: ', key.hex())
    print('IV: ', iv.hex())

    encrypted = aesEncrypt(message, key, iv)
    print('Encrypted: ', encrypted.hex())

    decrypted = aesDecrypt(encrypted, key, iv)
    print('Decrypted: ', decrypted.decode())
    assert message == decrypted


if __name__ == "__main__":
    main()
