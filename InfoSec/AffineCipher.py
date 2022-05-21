# 딕셔너리로 'A':0 ~ 'Z':25 매핑
def alpha():
    dic = {}
    for i in range(65, 91):
        dic[chr(i)] = i-65
    return dic


# 암호화
def encrypt(plain, a, s): # 평문과 곱셈, 덧셈 키를 입력 (a: 곱셈 키, s: 덧셈 키)
    enc = []
    dic = alpha()
    for i in plain:
        val = (a * dic[i] + s) % 26

        for key, value in dic.items():
            if value == val:
                enc.append(key)
    return enc


# 곱셈의 역원 찾기
def find_inverse(a):
    for i in range(26):
        if (a * i) % 26 == 1:
            return i


# 복호화
def decrypt(cypher, a, s): # 암호문과 곱셈, 덧셈 키를 입력
    dec = []
    dic = alpha()
    for i in cypher:
        inverse = find_inverse(a)

        if dic[i] - s < 0:   # 음수 처리
            temp = (dic[i]-s) + 26
        else:
            temp = dic[i] - s

        val = (temp * inverse) % 26
        for key, value in dic.items():
            if value == val:
                dec.append(key)
    return dec


def main():
    plain = input('평문을 입력하세요: ').replace(' ', '') # 공백 제거
    a = int(input('곱셈 키를 입력하세요: '))
    s = int(input('덧셈 키를 입력하세요: '))

    enc = ''.join(encrypt(plain, a, s))
    print('암호문: ' + enc)
    dec = ''.join(decrypt(enc, a, s))
    print('복호문: ' + dec)


if __name__ == "__main__":
    main()
