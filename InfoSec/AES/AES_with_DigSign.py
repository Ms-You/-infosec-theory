from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


# 키 생성
def gen_RSA_Key(userName):
    privateKey = RSA.generate(2048)  # 2048은 비트 수
    priKey = privateKey.exportKey('PEM')
    print("{} private Key: ".format(userName), priKey)

    pubKey = privateKey.publickey()
    print("{} public Key: ".format(userName), pubKey.exportKey('PEM'))

    return priKey, pubKey


# 서명 생성
def rsaDigSignGen(message, priKey):
    # 해시 값
    hashMsgObj = SHA512.new(message)
    privateKey = RSA.importKey(priKey)
    signGenObj = PKCS1_v1_5.new(privateKey)
    # 서명
    signMsg = signGenObj.sign(hashMsgObj)

    return signMsg


# AES 암호화
def aesEncryptWithSHA512(message, signature, key, iv):
    # 메시지 + 서명
    message += signature

    # 메시지 + 서명에 대한 AES 처리
    cipher_Encrypt = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher_Encrypt.encrypt(message)
    return ciphertext


# AES 복호화
def aesDecryptWithSHA(encrypted, key, iv):
    cipher_Decrypt = AES.new(key, AES.MODE_OFB, iv)
    decrypted = cipher_Decrypt.decrypt(encrypted)  # 메시지 + 해시(메시지)

    return decrypted


# 메시지와 서명 분리
def separateSigAndMessage(decrypted):
    # 메시지
    x = bytearray(decrypted)
    decryptedMsg = x[:-256]
    # 서명
    decrypted_Sig = x[len(x)-256:]

    return decrypted_Sig, decryptedMsg


# 검증
def rsaDigSignVerify(signMsg, message, pubKey):
    hashMsgObj = SHA512.new(message)
    signVerifyObj = PKCS1_v1_5.new(pubKey)
    if signVerifyObj.verify(hashMsgObj, signMsg):
        return True
    else:
        return False


def main():
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    message = b'Information security and Programming, Test Message!!! Name : Yu Myeong-Su'

    print('Message: ', message.decode())

    key = Random.new().read(KEY_SIZE)
    iv = Random.new().read(BLOCK_SIZE)

    print('AES Key: ', key.hex())
    print('IV: ', iv.hex())

    print("\n**RSA Key Pairs(priKey, pubKey) Generation")
    alice_priKey, alice_pubKey = gen_RSA_Key('Alice')
    bob_priKey, bob_pubKey = gen_RSA_Key('Bob')

    signMsg = rsaDigSignGen(message, alice_priKey)
    print("Length of Signature: ", len(signMsg))

    encryptedWithSHA512 = aesEncryptWithSHA512(message, signMsg, key, iv)
    print("AES Encryption E(Sign(H(M))+M): ", encryptedWithSHA512.hex())

    print("Length of Encrypted(Sign(H(M))+M): ", len(encryptedWithSHA512))
    print("Sending: ", encryptedWithSHA512.hex())
    print("**** Alice : sending Encrypted Message...")

    print("\n\n**** Bob : Receiving Encrypted Message...")
    print("Received: ", encryptedWithSHA512.hex())

    decryptedWithSHA512 = aesDecryptWithSHA(encryptedWithSHA512, key, iv)
    print("AES Decryption D(E(Sign(H(M))+M)): ", decryptedWithSHA512.hex())

    decrypted_Sig, decryptedMsg = separateSigAndMessage(decryptedWithSHA512)
    print("Decrypted Sign: ", decrypted_Sig.hex())
    print("Decrypted Message: ", decryptedMsg.decode())

    if rsaDigSignVerify(decrypted_Sig, decryptedMsg, alice_pubKey):
        print("Digital Signature Verification OK!!!")
    else:
        print("Digital Signature Verification Fail!!!")


if __name__ == "__main__":
    main()
