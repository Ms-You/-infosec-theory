from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def gen_RSA_Key(userName):
    privateKey = RSA.generate(2048)  # 2048은 비트 수
    priKey = privateKey.exportKey('PEM')
    print("{} private Key: ".format(userName), priKey)

    pubKey = privateKey.publickey()
    print("{} public Key: ".format(userName), pubKey.exportKey('PEM'))

    return priKey, pubKey


def rsaEncrypt(message, pubKey):
    rsaCipher = PKCS1_OAEP.new(pubKey)
    ciphertext = rsaCipher.encrypt(message)

    return ciphertext


def rsaDecrypt(encrypted, priKey):
    privateKey = RSA.importKey(priKey)
    rsaCipher = PKCS1_OAEP.new(privateKey)
    plaintext = rsaCipher.decrypt(encrypted)

    return plaintext


def main():
    message = b'Information security and Programming, Test Message!!! Name : Yu Myeong-Su'
    print("Message: ", message.decode())

    # 앨리스와 밥의 키 생성
    alice_priKey, alice_pubKey = gen_RSA_Key('alice')
    bob_priKey, bob_pubKey = gen_RSA_Key('bob')

    # 앨리스가 밥의 공개키로 메시지를 암호화해서 밥에게 전송함
    encrypted = rsaEncrypt(message, bob_pubKey)
    print("RSA_Encrypt(message, bob_pubKey): ", encrypted.hex())

    # 밥이 앨리스에게 받은 암호문을 밥 자신의 개인키로 복호화 함
    decrypted = rsaDecrypt(encrypted, bob_priKey)
    print("RSA_Decrypt(ciphertext, bob_priKey): ", decrypted.decode())


if __name__ == "__main__":
    main()
