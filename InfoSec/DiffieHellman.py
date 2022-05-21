from math import gcd


# 입력된 값 이하의 정수 중 가장 큰 소수값 리턴
def max_p(value):
    for num in range(value, 1, -1):
        for i in range(2, num):
            if num % i == 0:
                break
        else:
            return num


# p 값에 대한 생성자들 중 가장 큰 생성자 리턴
def max_g(p):
    root = []
    required_set = set(num for num in range (1, p) if gcd(num, p) == 1)

    for g in range(1, p):
        actual_set = set(pow(g, powers) % p for powers in range (1, p))
        if required_set == actual_set:
            root.append(g)           
    return max(root)


def main():
    num = int(input('입력된 값 이하의 가장 큰 소수값을 p 값으로 사용합니다.\n값을 입력해주세요: '))
    p = max_p(num)

    g = input('g값을 입력해주세요. \n\'자동\' 이라는 문자열을 입력할 시 p값에 대해 가장 큰 생성자가 자동 입력됩니다.\ng값: ')
    if g == '자동':
        g = max_g(p)
    else:
        g = int(g)
    alice_secret = int(input('Alice의 비밀 키 값을 입력해주세요: '))
    bob_secret = int(input('Bob의 비밀 키 값을 입력해주세요: '))

    ya = (g**alice_secret) % p
    yb = (g**bob_secret) % p

    k_alice = (yb**alice_secret) % p
    k_bob = (ya**bob_secret) % p

    print('-----------------------------------')
    print('p값: ', p)
    print('g값: ', g)
    print('-----------------------------------')
    print('Alice의 개인 키 값: ', alice_secret)
    print('Bob의 개인 키 값: ', bob_secret)
    print('-----------------------------------')
    print('Alice가 Bob에게 보내는 공개 키 값: ', ya)
    print('Bob이 Alice에게 보내는 공개 키 값: ', yb)
    print('-----------------------------------')
    print("Alice의 대칭 키: ", k_alice)
    print("Bob의 대칭 키: ", k_bob)


if __name__ == "__main__":
    main()
