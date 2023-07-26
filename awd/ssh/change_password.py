import paramiko
import concurrent.futures
from netaddr import IPNetwork

# SSH 用户名、密码、新密码和端口
username = 'your_username'
password = 'your_password'
new_password = 'your_new_password'
port = 22

# C网段
subnet = "192.168.1.0/24"

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
        ssh_session.send(password + '\n')  # 输入当前密码
        ssh_session.send(new_password + '\n')  # 输入新密码
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
    # 扫描 C 网段
    for ip in IPNetwork(subnet).iter_hosts():
        executor.submit(change_password, str(ip))
