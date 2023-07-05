# rsa coppersmith 相关攻击

## p高低位已知

### 条件

假设 p、q 二进制位数相同，如果p为`512`位，则p需已知约`288`位。如果p为`1024`位，则p需已知约`576`位。

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
