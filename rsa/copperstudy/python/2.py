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

n=0x7936335485ce5ca4932825de04b1a7eb369e52787a5457bd115e5fc0639fd9df1e27ddb527a69c08ee4c52c3e457afa91277cb1af71c281e99858acc62b77075072036f58f0a0bb40f5ab3462a4f18873c3c681304153a8c17caac65682c34cc752d81b758091e457f1ae5f0759995c341e099089297212de519363c59c5cb
e=65537
c=0x33e3d895b445ed22acc7ed9e771f27bc5314a671706ea95996a9f1ae8e9f1cc1e18effd0178d4953c30d9adb242aac8474fc666161c7fa12bcd2738d65435190882f0f7432fb5b57dddb94e7e047e499503921a1e9a5d664c03a7be770675b8482a65f63ba18c2d300c11c0a46d8d11334df50780af78d90d0b0eeba3f3c19
p_high = 0x1d59aab5e6eb96bffb7929c06715855cf2072f523ddb8efadc57d2707638a87ab3c68304b9aadd1b2fa897628eb73ea100000000000000000000000000000000 >> 128

p = recover_p(n, p_high, 0, 0, 128, 512)

if p!=0:
    q = n // p
    phi = (p-1)*(q-1)
    d = inverse_mod(e, phi)
    m = pow(c, d, n)
    print(hex(m))
