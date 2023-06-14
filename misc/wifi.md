# WiFi WPA四路握手及密码破解

## WPA四路握手过程

在WiFi网络协议中，WPA（Wi-Fi Protected Access）和WPA2协议使用名为四路握手（Four-way Handshake）的过程来生成加密密钥并验证网络和设备的信息。

1. **AP（Access Point，接入点）→客户端**：AP发送一个名为"ANonce"（Authenticator's Nonce，验证者的一次性随机数）的随机数到客户端。

2. **客户端→AP**：客户端收到ANonce后，使用它和自己的一次性随机数（SNonce，Supplicant's Nonce）以及预共享密钥（PSK，Pre-Shared Key）来计算出PMK（Pairwise Master Key）。然后，客户端将SNonce和MIC（Message Integrity Code，消息完整性代码）发送给AP。MIC是用于验证消息没有被篡改的一种校验码。

3. **AP→客户端**：AP接收到SNonce和MIC后，也使用ANonce、SNonce和PSK计算出PMK，然后用它来验证MIC是否正确。如果MIC正确，AP就知道客户端有正确的PSK。然后，AP会将ANonce、SNonce和一些额外的数据一起，生成一个名为PTK（Pairwise Transient Key）的临时密钥，并将一份新的MIC发送给客户端。

4. **客户端→AP**：客户端接收到新的MIC后，用自己生成的PTK来验证这个MIC是否正确。如果正确，客户端就知道AP有正确的PSK。然后，客户端会向AP确认已经接收到了正确的MIC。

通过上述四路握手过程，AP和客户端就可以确认彼此都知道正确的PSK，然后用PTK作为会话密钥来加密和解密数据。

## 字典攻击的可能性

**只需要抓取到开始的两个握手包，就能进行字典攻击。**

在四路握手的过程中，ANonce和SNonce是明文传输的，而PSK是由用户设置的密码通过PBKDF2算法转换得到的。攻击者如果能够抓取到握手过程的前两个包，就能够得到ANonce和SNonce，然后通过暴力破解或者字典攻击的方式，尝试各种可能的密码，转换成PSK，然后计算出PMK，如果这个计算出的PMK能够生成和抓取到的第二个握手包中的MIC相同的MIC，那么攻击者就可以认为尝试的这个密码是正确的。

## 字典攻击操作方法

因为字典攻击只需要用到WPA握手包，在实施字典攻击之前，因尽可能使用 `aircrack-ng` 附带的 `wpaclean` 工具对抓包文件进行握手包的提取，此后字典攻击只需要针对提取出来的握手包进行操作即可。

### 方法一：使用 `aircrack-ng`

```bash
aircrack-ng 握手包文件 -w 字典文件
```

### 方法二：使用 `john the ripper`

1. 提取 hash ：

    ```bash
    wpapcap2john 握手包文件 > hash_file
    ```

2. 对 hash_file 进行破解

    ```bash
    john -w=字典文件 -form=wpapsk hash_file
    ```

### 方法三：使用 `hashcat`

1. 提取 hash ：

   ```bash
   hcxpcapngtool 握手包文件 -o hash_file
   ```

2. 对 hash_file 进行破解

    ```bash
    hashcat -m 22000 -w 3 hash_file 字典文件
    ```
