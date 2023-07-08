# rsa coppersmith 相关攻击

## 素数因子p高低位已知

### 条件

1. 若p,q为`1024`位，当p或q缺失位数 `<= 454` 位时，可以通过coppersmith方法恢复p或q。
2. 若p,q为 `512`位，当p或q缺失位数 `<= 224` 位时，可以通过coppersmith方法恢复p或q。
3. 表达式 pk = n * inverse_mod(q % (2^k), 2^k) % 2^k ，实际上是求出**p的低k位**

### 脚本

```python
from sage.all import PolynomialRing, Zmod

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
    def recover_with_extension(p_high, p_missing_len, MAX_MISSING_LEN):
        p_high_extended_bits = p_missing_len - MAX_MISSING_LEN
        p_high_extended = p_high << p_high_extended_bits                
        for _ in range(1 << p_high_extended_bits):
            p = phl(n, p_high_extended, p_low, p_low_len, MAX_MISSING_LEN)
            if p != 0:
                return p            
            p_high += 1
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
        return recover_with_extension(p_high, p_missing_len, MAX_MISSING_LEN)

```

## 明文m高低位已知

### 条件

1. e足够小。
2. m缺失位数 <= n^(1/e)。

### 脚本

```python
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

```
