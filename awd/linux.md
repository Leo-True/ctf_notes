# linux常用命令

## 系统

```bash
# 修改密码
passwd
```

## 网络

```bash
# 查看网络接口IP地址、掩码、广播地址
ifconfig

ip a

# 查看网关
route -n

ip r

# 查看DNS服务器
cat /etc/resolv.conf

# 列出处于监听状态的端口
netstat -tuln

# 网络主机发现
nmap -sP 192.168.3.0/24

sudo nmap -sS 192.168.3.0/24

nmap -p 22 192.168.1.0/24 -oG - | awk '/open/{print $2}' > ip.txt

nmap -sS -p 22 192.168.1.0/24 -oG - | awk '/open/{print $2}' > ip.txt
```

## 文件

### 复制文件夹

```bash
cp -r source_dir dest_dir
```

### 删除文件夹

```bash
rm -r source_dir dest_dir
```

### 查找文件

#### 在所有目录下查找文件名为`flag`的文件

```bash
find / -name flag 2>/dev/null
```

#### 在当前目录及子目录下查找最近20分钟内修改过的文件

```bash
find . -mmin -20
```

#### 列出当前目录及子目录下所有非空文件，包括隐藏文件，按文件大小排序，小文件居前

```bash
du -ah . | grep -v '^0' | sort -h
```
