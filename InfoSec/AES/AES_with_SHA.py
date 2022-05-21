from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512


def aesEncryptWithSHA512(message, key, iv):
    # message 해시 처리
    hash_Func = SHA512.new()
    hash_Func.update(message)
    hashOfMsg = hash_Func.digest()
    print("SHA512(Message): ", hashOfMsg.hex())

    # 메시지 + 해시(메시지)
    message += hashOfMsg

    # 메시지 + 해시(메시지)에 대한 AES 처리
    cipher_Encrypt = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher_Encrypt.encrypt(message)
    return ciphertext


def aesDecryptWithSHA(encrypted, key, iv):
    # AES 복호화
    cipher_Decrypt = AES.new(key, AES.MODE_OFB, iv)
    decrypted = cipher_Decrypt.decrypt(encrypted)  # 메시지 + 해시(메시지)

    # 메시지 부분 찾기
    # 해시(메시지) 가 64 바이트니까 잘라내면 메시지가 나옴

    # 메시지
    x = bytearray(decrypted)
    decryptedMsg = x[:-64]
    # 해시(메시지)
    decrypted_SHA = x[len(x)-64:]

    return decrypted_SHA, decryptedMsg


# 검증
def verifySHA512(decryptedSHA512, decryptedMsg):
    hash_Func = SHA512.new()
    hash_Func.update(decryptedMsg)

    return decryptedSHA512.hex() == hash_Func.hexdigest()


def main():
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    message = b'Information security and Programming, Test Message!!! Name : Yu Myeong-Su'

    print('Message: ', message.decode())

    key = Random.new().read(KEY_SIZE)
    iv = Random.new().read(BLOCK_SIZE)

    print('AES Key: ', key.hex())
    print('IV: ', iv.hex())

    encryptedWithSHA512 = aesEncryptWithSHA512(message, key, iv)
    print("Encrypted E(H(M) || M): ", encryptedWithSHA512.hex())

    decryptedSHA512, decryptedMsg = aesDecryptWithSHA(encryptedWithSHA512, key, iv)
    print("Decrypted SHA512: ", decryptedSHA512.hex())

    if verifySHA512(decryptedSHA512, decryptedMsg):
        print("Integrity OK, Correct Hash!!")
    else:
        print("Incorrect Hash!!")

    print('Decrypted: ', decryptedMsg.decode())
    assert message == decryptedMsg


if __name__ == "__main__":
    main()
