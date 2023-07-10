# 已知明文m高位m_high和低位m_low，恢复m。m_missing_len <= n^(1/e)
from sage.all import PolynomialRing, Zmod

def recover_m(n, e, c, m_high, m_low, m_low_len, m_missing_len):
    # 创建一个多项式环，定义变量x，模为n
    PR = PolynomialRing(Zmod(n), name='x')
    x = PR.gen()
    # 构建多项式
    msg = (m_high << (m_missing_len + m_low_len)) + (1 << m_low_len) * x + m_low 
    f = msg ** e - c
    # 将多项式转化为首系数为1的形式
    fm = f.monic()
    # 寻找多项式的小根
    roots = fm.small_roots(X = 1<<m_missing_len, beta = 0.4)

    if roots:
        return int(msg(roots[0]))
    else:
        return None


n=0xadf364c509381f9f52fb2ed3676b47abd384af6814cb30c3480f562470eb6b1e30a93cf9493e98587a97b05725a3dd7af7a0a906bd1583e8ced2d1457954fb250b827002e148e8c58f7414f4351c51c62d538f1c10c0404c98d103db69dfdb02c5354871b179f854fcc4d2ec8d83855c764fa766578617888a6ec2668260fca3
e=3
c=0x9471a9e909eb5f3c933be2beed8a6b1515041110fca47701e64fa36adb8748a10ba939571e7904849f4c0666c5aed8cf7d8c4978cc5e18f564fe0bb0311e22b4a04c5ccae6603bbb65adaa9668d9ca6fc479960bb94546eaa1de75877ce1c40262d21894e966a4436128d9edf49d72f71df1d5c77ee0dc976e97c5740f07828d
m_high=0x6696af2b1064c860a38acab284af83d0659c8a6f7aca6e147ecb5874a47108074608c619b5f001b03558da7e0c4546e3c8318ef70e2878000000000000000000 >> 72

m = recover_m(n, e, c, m_high, 0, 0, 72)

if m:
    print(hex(m))
