from fabric import Connection
from concurrent.futures import ThreadPoolExecutor
from netaddr import IPNetwork

# SSH 用户名、密码、新密码和端口
username = 'your_username'
password = 'your_password'
new_password = 'your_new_password'
port = 22

# C网段
subnet = "192.168.1.0/24"

def change_password(ip):
    try:
        # 创建连接
        conn = Connection(host=ip, user=username, port=port, connect_kwargs={"password": password})
        
        # 修改密码
        conn.run('echo "{}:{}" | chpasswd'.format(username, new_password))
        print(f'IP {ip} password changed successfully')
        
    except Exception as e:
        print(f"Failed to change password for IP {ip}, error: {e}")

# 使用线程池进行并发处理
with ThreadPoolExecutor(max_workers=50) as executor:
    # 扫描 C 网段
    for ip in IPNetwork(subnet).iter_hosts():
        executor.submit(change_password, str(ip))
