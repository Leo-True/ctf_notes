# 2019 强网杯 CopperStudy

## 0x00 proof

### 题目

> [+] skr=os.urandom(8)  
> [+] hashlib.sha256(skr).hexdigest()=520dc1cebc492b91dcc96787a791c182328d54adb63afef73c485e93f714627a  
> [+] skr[0:5].encode('hex')=497625a6d2  
> [-] skr.encode('hex')=  

### 求解

`skr`为`8`个字节，已经知道`5`个字节，只需要对未知的`3`个字节的值试错穷举即可。

```python
import hashlib
from itertools import product

known_message = bytes.fromhex('497625a6d2')
known_hash = '520dc1cebc492b91dcc96787a791c182328d54adb63afef73c485e93f714627a'

def calculate_hash(message):
    return hashlib.sha256(message).hexdigest()

def bruteforce():
    # 3字节的所有可能性，每个字节可以是0-255之间的任何值
    for i in product(range(256), repeat=3):
        guess = known_message + bytes(i)
        if calculate_hash(guess) == known_hash:
            return guess

result = bruteforce()
print(result.hex())
```

### 答案

> 497625a6d2bfc327

---

## 0x01 Challenge1

### 题目

> [+] n=0xadf364c509381f9f52fb2ed3676b47abd384af6814cb30c3480f562470eb6b1e30a93cf9493e98587a97b05725a3dd7af7a0a906bd1583e8ced2d1457954fb250b827002e148e8c58f7414f4351c51c62d538f1c10c0404c98d103db69dfdb02c5354871b179f854fcc4d2ec8d83855c764fa766578617888a6ec2668260fca3L  
> [+] e=3  
> [+] m=random.getrandbits(512)  
> [+] c=pow(m,e,n)=0x9471a9e909eb5f3c933be2beed8a6b1515041110fca47701e64fa36adb8748a10ba939571e7904849f4c0666c5aed8cf7d8c4978cc5e18f564fe0bb0311e22b4a04c5ccae6603bbb65adaa9668d9ca6fc479960bb94546eaa1de75877ce1c40262d21894e966a4436128d9edf49d72f71df1d5c77ee0dc976e97c5740f07828dL  
> [+] ((m>>72)<<72) =0x6696af2b1064c860a38acab284af83d0659c8a6f7aca6e147ecb5874a47108074608c619b5f001b03558da7e0c4546e3c8318ef70e2878000000000000000000L  
> [-] long_to_bytes(m).encode('hex')=  

### 求解

明文`m`缺失`72`位，`e`的值很小，可以恢复明文`m`。

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


n=0xad...
e=3
c=0x94...
m_high=0x66... >> 72

m = recover_m(n, e, c, m_high, 0, 0, 72)

if m:
    print(hex(m))
```

### 答案

> 6696af2b1064c860a38acab284af83d0659c8a6f7aca6e147ecb5874a47108074608c619b5f001b03558da7e0c4546e3c8318ef70e2878a57b2913fe55ef3e07

---

## 0x02 Challenge2

### 题目

> [+] n=0x7936335485ce5ca4932825de04b1a7eb369e52787a5457bd115e5fc0639fd9df1e27ddb527a69c08ee4c52c3e457afa91277cb1af71c281e99858acc62b77075072036f58f0a0bb40f5ab3462a4f18873c3c681304153a8c17caac65682c34cc752d81b758091e457f1ae5f0759995c341e099089297212de519363c59c5cbL  
> [+] e=65537  
> [+] m=random.getrandbits(512)  
> [+] c=pow(m,e,n)=0x33e3d895b445ed22acc7ed9e771f27bc5314a671706ea95996a9f1ae8e9f1cc1e18effd0178d4953c30d9adb242aac8474fc666161c7fa12bcd2738d65435190882f0f7432fb5b57dddb94e7e047e499503921a1e9a5d664c03a7be770675b8482a65f63ba18c2d300c11c0a46d8d11334df50780af78d90d0b0eeba3f3c19L  
> [+] ((p>>128)<<128)=0x1d59aab5e6eb96bffb7929c06715855cf2072f523ddb8efadc57d2707638a87ab3c68304b9aadd1b2fa897628eb73ea100000000000000000000000000000000L  
> [-] long_to_bytes(m).encode('hex')=  

### 求解

素数因子`p`缺失`128`位，可以恢复`p`，求出私钥因子`d`，再对密文`c`解密即可。

```python
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

n=0x79...
e=65537
c=0x33...
p_high = 0x1d... >> 128

p = recover_p(n, p_high, 0, 0, 128, 512)

if p!=0:
    q = n // p
    phi = (p-1)*(q-1)
    d = inverse_mod(e, phi)
    m = pow(c, d, n)
    print(hex(m))

```

### 答案

> d73f80417d7ee47efe2c521377cc0ec16d29352fb3a2b9b9e83a6fb1f28b1cd87bc04c9ce13822636c1b20b7a417557ea3bb0232d2ad24f1114b388279bef86e

---
