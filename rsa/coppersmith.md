# rsa coppersmith 相关攻击

## p高低位已知

### 条件

1. 若p,q为`1024`位，当p或q缺失位数 `<= 454` 位时，可以通过coppersmith方法恢复p或q。
2. 若p,q为 `512`位，当p或q缺失位数 `<= 224` 位时，可以通过coppersmith方法恢复p或q。
3. 表达式 pk = n * inverse_mod(q % (2^k), 2^k) % 2^k ，实际上是求出**p的低k位**

### sage 脚本

```python
# 已知p高位，恢复p
def ph(n, p_high, p_missing_len):
    PR.<x> = PolynomialRing(Zmod(n))
    f = (p_high << p_missing_len) + x
    roots = f.small_roots(X = 1<<p_missing_len, beta = 0.4)
    if roots:
        return int(f(roots[0]))
    else:
        return 0

# 已知p低位，恢复p
def pl(n, p_low, p_low_len, p_missing_len):
    PR.<x> = PolynomialRing(Zmod(n))    
    f = (1 << p_low_len) * x + p_low
    fm = f.monic()
    roots = fm.small_roots(X = 1<<p_missing_len, beta = 0.4)
    if roots:
        return int(f(roots[0]))
    else:
        return 0

# 已知p高位和低位，恢复p
def phl(n, p_high, p_low, p_low_len, p_missing_len):
    PR.<x> = PolynomialRing(Zmod(n))    
    f = (p_high << (p_missing_len + p_low_len)) + (1 << p_low_len) * x + p_low
    fm = f.monic()
    roots = fm.small_roots(X = 1<<p_missing_len, beta = 0.4)
    if roots:
        return int(f(roots[0]))
    else:
        return 0
```
