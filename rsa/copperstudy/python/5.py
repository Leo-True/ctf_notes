from sage.all import *

def franklin_reiter_attack(e, n, c1, c2, a, b):
    """
    实现对 RSA 的 Franklin-Reiter 相关消息攻击。

    参数:
    
    e (int): 公钥指数
    
    n (int): 模数

    c1 (int): 第一条消息的 RSA 加密值

    c2 (int): 第二条消息的 RSA 加密值

    a (int): m2 = a*m1 + b 中的系数 a

    b (int): m2 = a*m1 + b 中的系数 b

    返回:

    int: 第一条原始消息
    """

    x = PolynomialRing(ZZ.quo(n*ZZ), 'x').gen()
    f1 = x**e - c1
    f2 = (a*x+b)**e - c2

    a = f2
    b = f1
    rp = 0
    while True:
        r = a % b
        if r == 0:
            c = rp.coefficients()
            m1 = -pow(c[1], -1, n) * c[0]
            return m1

        rp = r
        a, b = b, r
 

n=0x22218c4cfeb7501dd440f892feaa980706103d305466668f51d1a89f527cc51ed17dddafa69c14136b4d0405de606a48d0d1a8b56e1cb8865e545d9684b83f7d3b2a96d678d6a1ef80a515aa0972469d2370695fee2da3e3b51bfd5601547140102cf98858abff19caadffd75d4636a08b5a02a9510edcbe9cdc35de275bdde3
e=3
c1=0x1978dc15831038656b6935083b104e51adb0d6d4c1b2dd3025296d6ec60320a24edc00c57ba81c97355d4f32b2b5a3136da3ba26f9f3454b3fd572843d0618b3aadeec346f6df508ccd5ddb0cc38c45da6d2e7f4820ab44fe08e176ae5fc730c77473c6460fd3527b2d710bb9db08af768b005e2078f35103a5011cd9bacd06f
c2=0x20ef9d6ac2cc12c45847f99c5004fb26d37e5d31862f89a4244095fbcf0a1f9b1276d98f02abd7dadc951fa8b218bea449c1b022732029b52e88492e6bbd787ea896e72ea425eb18ea616d454575f65e9380f028d23e35e714c3e91b0a1c38742c4a25c143fea6f60099771f74384c7256fee7309a841548ce0571fdb466fbe7

a=1
b=1

m1 = franklin_reiter_attack(e, n, c1, c2, 1, 1)
if m1 is not None:
    print(hex(m1))
