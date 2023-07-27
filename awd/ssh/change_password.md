# 批量修改主机ssh密码

假设要修改的主机IP地址在文件`ip.txt`中，每行一个ip地址。这样的文件可以通过namp扫描生成，例：

```bash
# 端口扫描。假设ssh服务监听端口为22
nmap -p 22 192.168.1.0/24 -oG - | awk '/open/{print $2}' > ip.txt

# 半开扫描，可能更快，需sudo
sudo nmap -sS -p 22 192.168.1.0/24 -oG - | awk '/open/{print $2}' > ip.txt
```

如果需要列出所登录主机监听的端口，可使用如下命令：

```bash
netstat -tuln
```

批量修改主机ssh密码脚本，用户名、密码、并发线程数、超时值等请根据实际需要修改：

```python
import paramiko
import concurrent.futures
import time

# SSH 用户名、密码、新密码和端口
username = 'user1'
password = '123456'
new_password = 'mN66##88ga'
port = 22

# IP 地址文件
ip_file = 'ip.txt'

def change_password(ip):
    # 创建 SSH 客户端
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # 尝试连接到远程服务器
        client.connect(ip, port=port, username=username, password=password, timeout=5)
        
        # 创建新的 ssh 会话
        ssh_session = client.invoke_shell()
        
        # 建立 ssh 会话后，输入密码修改命令，这里假设是 Linux 系统，使用 passwd 命令
        ssh_session.send('passwd\n') 
        time.sleep(0.5)  # 加入等待时间
        ssh_session.send(password + '\n')  # 输入当前密码
        time.sleep(0.5)  # 加入等待时间
        ssh_session.send(new_password + '\n')  # 输入新密码
        time.sleep(0.5)  # 加入等待时间
        ssh_session.send(new_password + '\n')  # 再次输入新密码
        
        # 等待命令执行完毕
        while not ssh_session.recv_ready():
            time.sleep(0.5)
            
        # 输出命令执行结果
        print(f'IP {ip} password changed successfully')
        
    except Exception as e:
        print(f"Failed to change password for IP {ip}, error: {e}")
        
    finally:
        # 关闭连接
        client.close()

# 使用线程池进行并发处理
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    # 读取 IP 地址文件
    with open(ip_file, 'r') as f:
        ip_list = [line.strip() for line in f]
    
    # 扫描 IP 地址
    for ip in ip_list:
        executor.submit(change_password, ip)

```
