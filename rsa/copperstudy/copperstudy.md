# 2019 强网杯 CopperStudy

## 0x00 proof 哈希穷举

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

## 0x01 Challenge1 小指数e，已知部分m

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

## 0x02 Challenge2 已知部分p

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

## 0x03 Challenge3 小指数e，已知部分d

### 题目

> [+] n=0x5a3579c3f68f37e725e5a6c0bdb931dec0b7a34251726b08016f57c502536d9642f2bf59aa1fb3ff65705fff7715cae3b37bc21010d9b1be3acc56f6ecf4bd4a534582edfad4255b62d2fffe7413e4d953e64c519e5e1b03a4646c12d20cc7df29e1770446f629d1077f423bae85fe074fc6549a85e3471272cc91c5854a586dL  
> [+] e=3  
> [+] m=random.getrandbits(512)  
> [+] c=pow(m,e,n)=0x1d5e18525c42810ac350b13fc798c0559ba72a888a1d716be88506122387c07532e928b5de020bcf5cc09867b718b6621d78dfb303242853423182d7820892d70f7b16742011019bf8de5cdf64d1a3f9942a48733dd580db5f678fb2d61788942d85bbf3a025a681504250a44a15720091609491428cd09899489d8a958f9334L  
> [+] d=invmod(e,(p-1)*(q-1))  
> [+] d&((1<<512)-1)=0xc1e99958fb6b655de9ffc67a36acd32e767deda4c2afa68f620a7bc85516c937848443636c4bd1f747e3140d74d74a001f114e3d5ab52b7cd32ae49563d52cabL  
> [-] long_to_bytes(m).encode('hex')=  

### 求解

已知私钥因子`d`的`低512位`，且`e`很小。
ed = 1 mod (p-1)(q-1) =>  
ed = 1 + k(p-1)(q-1) , k < e  
两边对 `2^512` 取模 =>  
e * d_low = (1 + k(p-1)(q-1)) mod 2^512 =>  
e * d_low * p = (p + k * (np - p^2 - n + p)) mod 2^512

这个方程是模意义下的一元二次方程，解出来之后得到`p`的`低512位`，再用coppersmith方法恢复`p`即可。

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


def p_lows_from_d_low(n, e, d_low, d_low_len):
    p_lows = []
    for k in range(1, e):
        p = var('p')
        roots = solve_mod([e*d_low*p  == p + k*(n*p - p**2 - n + p)], 2**d_low_len)
        p_lows += [int(r[0]) for r in roots]
    
    return p_lows


n = 0x5a...
e = 3
d_low = 0xc1...
d_low_len = 512
c = 0x1d...

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
```

### 答案

> c9a90c63a308112ff26cdb492becc6504667b567aa10fd0eb7209391e06312fdff9f21bb5c2bd1dd85ceede33894ab8c0485253954106662e0835991f22878c8

---

## 0x04 Challenge4 小指数e，同一明文多则密文，广播攻击

### 题目

> [+] e=3  
> [+] m=random.getrandbits(512)  
> [+] n1=0x1ec2150f6e573adba01b2fe569ae7a0a2d02d82d788c6571ddfdb411af18666e7b64c47defa9e292682ad4e5b07d690e372cf5baad656fd222701d8acc68bf35646a4343c5aa88de2e8859abac9884a72c7a4525b813644f8f806465feb0a03b6d734995a7ed5a751a49e35d1c4bac592aefd91dee81f1fa9ac027fc3647d4ebL  
> [+] c1=pow(m,e,n1)=0xb081a5dbd2ab11925407875e217aa98754e944c4fda52a3341d1cb0bd4c6621a64757e119601918665c9877a33241c3d2483c00cf822dacf257617b6f0dc8de05d4b59ed5958f52dfce50b014d900ffe4d9e375824bc648adb72ecc4c4ecdc9f3be49fced7424d0ed696b6e98b1f6ddeaa79ebca0a592ba05bc11f98aa9ab1cL  
> [+] n2=0x1ca49ec4a77cfcfcbbf393e9772538c2adf63d0649226bb2aa357178c0a56f6481c39b7e96da90750bd73b067e8b52e2133bdba9f9bde8d868cd682826c2ee10a7a2958b887b07df1e05e38b515da13c4346b948831af253744e2b7cc90a9414fa5b4ada0327236ae29a7b010d8d9e6529491566e7fb71c91746e43bbd6ebe8fL  
> [+] c2=pow(m,e,n2)=0xf570f81b5fb68810dce6811a3a6c86c507e250ac903f412cd89bfc572652b9376b03105e410754422583d9a6522f607a9bcceb14357688a5b1eeafc87066b6304872091ff1760ad6a9d8d72d4cb64b51b559cbb8c7d790303d9fa491fc3f7d6e6bde370cff2c89528978fbfaf2724e63b3347e3cc0129e1b79056c0e9653deL  
> [+]n3=0x1f3497868702f5500fc66239f280303bb2129f10c3607ff4aca342ecdb1850bbaf9404b0e7533e6a6d0bdc71bb3336393da5bed3c6f7ab8c4e63b9e37c05a09a3c91269c3385b19759f36b9b1ebbcc4245a1c46ddedcbe80865701942e38cedc82b54630659772e8de8b33064fad6d5551c2e19ed8fa20541d2ca3818d5bc6e1L  
> [+] c3=pow(m,e,n3)=0x480830044351b6d4f86b9968e56a5a3b18b1f966851229f3a500f870d8a3ad364944c18701d67cf02f876a5ec353935ee4d3d7e313f0db0867da70a40458577764540ef60446c7a71577598498b89f2d706013936c9eb9b0f730a27d197dc64370a1e772fcca8ae59a56a0de0dbcbd0d92228df2efd3fb64dcf87a27e842c1eL  
> [-] long_to_bytes(m).encode('hex')=  

### 求解

这里用同一个`e`，不同的`n`，对同一则明文进行了加密，且`e`的值较小。

首先判断所有`n`是否两两互质，否则可以通过gcd求公因子，从而直接分解n。判断脚本：

```python
from sage.all import *

def are_all_coprime(numbers):
    for i in range(len(numbers)):
        for j in range(i+1, len(numbers)):
            if not is_coprime(numbers[i], numbers[j]):
                return False
    return True
```

若所有`n`两两互质，由：

> c_1 = m^e mod n_1
> c_2 = m^e mod n_2
> ...
> c_e = m^e mod n_e

根据中国剩余定理，可解出 `m^e` ，从而求得 `m`。

```python
from sage.all import *

def are_all_coprime(numbers):
    count = len(numbers)
    for i in range(count):
        for j in range(i+1, count):
            if not gcd(numbers[i], numbers[j]) == 1:
                print(f"Not coprime: [{i}] - [{j}]")
                return False
    return True


n1 = 0x1e...
n2 = 0x1c...
n3 = 0x1f...

c1 = 0xb0...
c2 = 0xf5...
c3 = 0x48...

if are_all_coprime([n1, n2, n3]):
    m = crt([c1, c2, c3], [n1, n2, n3]).nth_root(3)
    print(hex(m))
```

### 答案

> f41982eb32ff1cac23d5f9db26a5671aeca57c9b3f40465a1ec5b825aa699e0a9b5cc09d167de63f90c50ca55f79e4dc20c574aefeb2bbe076c4f3b91715849b

## 0x05 Challenge5 Franklin-Reiter 相关消息攻击

### 题目

> [+] n=0x22218c4cfeb7501dd440f892feaa980706103d305466668f51d1a89f527cc51ed17dddafa69c14136b4d0405de606a48d0d1a8b56e1cb8865e545d9684b83f7d3b2a96d678d6a1ef80a515aa0972469d2370695fee2da3e3b51bfd5601547140102cf98858abff19caadffd75d4636a08b5a02a9510edcbe9cdc35de275bdde3L  
> [+] e=3  
> [+] m=random.getrandbits(512)  
> [+] c=pow(m,e,n)=0x1978dc15831038656b6935083b104e51adb0d6d4c1b2dd3025296d6ec60320a24edc00c57ba81c97355d4f32b2b5a3136da3ba26f9f3454b3fd572843d0618b3aadeec346f6df508ccd5ddb0cc38c45da6d2e7f4820ab44fe08e176ae5fc730c77473c6460fd3527b2d710bb9db08af768b005e2078f35103a5011cd9bacd06fL  
> [+] x=pow(m+1,e,n)=0x20ef9d6ac2cc12c45847f99c5004fb26d37e5d31862f89a4244095fbcf0a1f9b1276d98f02abd7dadc951fa8b218bea449c1b022732029b52e88492e6bbd787ea896e72ea425eb18ea616d454575f65e9380f028d23e35e714c3e91b0a1c38742c4a25c143fea6f60099771f74384c7256fee7309a841548ce0571fdb466fbe7L  
> [-] long_to_bytes(m).encode('hex')=  

### 题解

`e=3`，被同样的密钥加密的两则`明文线性相关`(m, m+1)，适用 `Franklin-Reiter 相关消息攻击`。

```python
```

### 答案
