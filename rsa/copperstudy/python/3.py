from sage.all import *

# 已知p高位p_high和低位p_low，恢复p
def phl(n, p_high, p_low, p_low_len, p_missing_len):
    # 创建一个多项式环，定义变量x，模为n
    PR = PolynomialRing(Zmod(n), name='x')
    x = PR.gen()
    # 构建多项式
    f = (p_high << (p_missing_len + p_low_len)) + (1 << p_low_len) * x + p_low
    # 将多项式转化为首系数为1的形式
    fm = f.monic()
    # 寻找多项式的小根
    roots = fm.small_roots(X = 1<<p_missing_len, beta = 0.4)
    # 如果存在解，返回第一个解代入多项式的结果
    if roots:
        return int(f(roots[0]))
    else:
        return 0


# 已知p高位p_high和低位p_low，恢复p，缺失位数过多则穷举
def recover_p(n, p_high, p_low, p_low_len, p_missing_len, p_len = 1024):
    # 定义一个函数，处理p_high的扩展和恢复
    def recover_with_extension():
        p_high_extended_bits = p_missing_len - MAX_MISSING_LEN
        p_high_extended = p_high << p_high_extended_bits                
        for _ in range(1 << p_high_extended_bits):
            p = phl(n, p_high_extended, p_low, p_low_len, MAX_MISSING_LEN)
            if p != 0:
                return p            
            p_high_extended += 1
        return 0

    # 验证p_len的值，只处理1024和512两种情况
    if p_len != 1024 and p_len != 512:
        return phl(n, p_high, p_low, p_low_len, p_missing_len)
    
    # 设置对应p_len的最大缺失长度
    MAX_MISSING_LEN = 454 if p_len == 1024 else 224

    # 如果缺失长度小于最大缺失长度，直接调用phl恢复
    if p_missing_len <= MAX_MISSING_LEN:
        return phl(n, p_high, p_low, p_low_len, p_missing_len)
    # 否则，进行p_high的扩展和恢复
    else:
        return recover_with_extension()


def p_lows_from_d_low(n, e, d_low, d_low_len):
    p_lows = []
    for k in range(1, e):
        p = var('p')
        roots = solve_mod([e*d_low*p  == p + k*(n*p - p**2 - n + p)], 2**d_low_len)
        p_lows += [int(r[0]) for r in roots]
    
    return p_lows


n = 0x5a3579c3f68f37e725e5a6c0bdb931dec0b7a34251726b08016f57c502536d9642f2bf59aa1fb3ff65705fff7715cae3b37bc21010d9b1be3acc56f6ecf4bd4a534582edfad4255b62d2fffe7413e4d953e64c519e5e1b03a4646c12d20cc7df29e1770446f629d1077f423bae85fe074fc6549a85e3471272cc91c5854a586d
e = 3
d_low = 0xc1e99958fb6b655de9ffc67a36acd32e767deda4c2afa68f620a7bc85516c937848443636c4bd1f747e3140d74d74a001f114e3d5ab52b7cd32ae49563d52cab
d_low_len = 512
c = 0x1d5e18525c42810ac350b13fc798c0559ba72a888a1d716be88506122387c07532e928b5de020bcf5cc09867b718b6621d78dfb303242853423182d7820892d70f7b16742011019bf8de5cdf64d1a3f9942a48733dd580db5f678fb2d61788942d85bbf3a025a681504250a44a15720091609491428cd09899489d8a958f9334

p_low_len = d_low_len
p_missing_len = 128
p_len = p_low_len + p_missing_len

p_lows = p_lows_from_d_low(n, e, d_low, d_low_len)
for p_low in p_lows:
    p = recover_p(n, 0, p_low, p_low_len, p_missing_len, p_len)
    if p:
        break

q = n // p
phi = (p-1) * (q-1)
d = inverse_mod(e, phi)
m = pow(c, d, n)

print(hex(m))
