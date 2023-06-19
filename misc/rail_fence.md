# 栅栏密码解密

```python
from collections import deque

def rail_fence_decrypt(ciphertext: str, num_rails: int) -> str:
    """
    解密栅栏密码。

    参数：
    ciphertext -- 密文（字符串）
    num_rails -- 栅栏的数量（整数）

    返回：
    解密后的明文（字符串）
    """
    ciphertext = list(ciphertext)

    # 计算每一层的字符数量
    rail_lengths = [0] * num_rails
    for i in range(len(ciphertext)):
        rail_lengths[i % num_rails] += 1

    # 生成栅栏
    rail_indexes = [sum(rail_lengths[:i]) for i in range(num_rails+1)]
    rails = [deque(ciphertext[rail_indexes[i]:rail_indexes[i+1]]) for i in range(num_rails)]

    # 把栅栏里的字符按照原来的顺序重新排列
    plaintext = ""
    for i in range(len(ciphertext)):
        plaintext += rails[i % num_rails].popleft()

    return plaintext
```
