from Crypto.Cipher import AES
from Crypto import Random
from AES.AES_Test import aesEncrypt, aesDecrypt
from RSA.RSA_and_DigSign import rsaEncrypt, rsaDecrypt
from RSA.RSA_Test_with_File import read_RSA_Private_Key_from_File, read_RSA_Public_Key_from_File


def hybridEncrypt(plaintext):
    sessionKey = Random.new().read(AES.block_size)
    print("Generated Session Key: %s" % sessionKey.hex())
    iv = Random.new().read(AES.block_size)
    print("IV, plaintext : %s, %s" % (iv.hex(), plaintext))
    encMSG = iv + aesEncrypt(plaintext, sessionKey, iv)
    bob_pubKey_read = read_RSA_Public_Key_from_File("Bob")
    encSSK = rsaEncrypt(sessionKey, bob_pubKey_read)
    print("length of encSSK & encrypted session key : %s %s" % (len(encSSK), encSSK.hex()))
    encrypted = encSSK + encMSG
    print("encrypted output: %s" % encrypted.hex())
    return encrypted


def hybridDecrypt(encrypted):
    RSA_CIPHER_SIZE = 256
    bob_priKey_read = read_RSA_Private_Key_from_File("Bob")
    decSSK = rsaDecrypt(encrypted[:RSA_CIPHER_SIZE], bob_priKey_read)
    print("Decrypt Session Key: %s" % decSSK.hex())
    encMSG = encrypted[RSA_CIPHER_SIZE:]
    iv2 = encMSG[:AES.block_size]
    decrypted = aesDecrypt(encMSG[AES.block_size:], decSSK, iv2)
    return decrypted


def main():
    plaintext = b'Myeong-suYu Good'; print("PlainText: ", plaintext)
    encrypted = hybridEncrypt(plaintext)
    decrypted = hybridDecrypt(encrypted)
    print("decrypted PlainText: ", decrypted)


if __name__ == "__main__":
    main()

