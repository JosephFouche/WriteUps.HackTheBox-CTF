# First we do the nmap routine
What we see is: 

Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-11 16:04 -03
Nmap scan report for voleur.htb (10.10.11.76)
Host is up (0.21s latency).
Not shown: 65516 filtered tcp ports (no-response)

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus

88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-12 03:12:58Z)

135/tcp   open  msrpc         Microsoft Windows RPC

139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn

389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)

445/tcp   open  microsoft-ds?

464/tcp   open  kpasswd5?

593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

636/tcp   open  tcpwrapped

2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)

3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)

3269/tcp  open  tcpwrapped

9389/tcp  open  mc-nmf        .NET Message Framing

49668/tcp open  msrpc         Microsoft Windows RPC

63831/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

63832/tcp open  msrpc         Microsoft Windows RPC

63843/tcp open  msrpc         Microsoft Windows RPC

63851/tcp open  msrpc         Microsoft Windows RPC

63865/tcp open  msrpc         Microsoft Windows RPC

Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2025-10-12T03:13:58
|_  start_date: N/A
|_clock-skew: 7h59m58s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 589.54 seconds

# Se procede con actualizacion de reloj y pedido de ticket de kerberos despues de exporta a carpeta de ctf
pasamos a hace ldap y smb y recolectamos con bloodhound
(pc㉿kali)-[~]
└─$ impacket-getTGT voleur.htb/'ryan.naylor':'HollowOct31Nyt'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
                                                                                                                                                                     
┌──(pc㉿kali)-[~]
└─$ sudo systemctl status systemd-timesyncd
● systemd-timesyncd.service - Network Time Synchronization
     Loaded: loaded (/usr/lib/systemd/system/systemd-timesyncd.service; enabled; preset: enabled)
     Active: active (running) since Mon 2025-10-13 13:35:52 -03; 2h 13min ago
 Invocation: 4f9b8903ad3f48cd91233e217be4fb62
       Docs: man:systemd-timesyncd.service(8)
   Main PID: 607 (systemd-timesyn)
     Status: "Contacted time server [2606:4700:f1::123]:123 (2.debian.pool.ntp.org)."
      Tasks: 2 (limit: 76488)
     Memory: 3M (peak: 4.2M)
        CPU: 48ms
     CGroup: /system.slice/systemd-timesyncd.service
             └─607 /usr/lib/systemd/systemd-timesyncd

Oct 13 13:35:52 kali systemd[1]: Starting systemd-timesyncd.service - Network Time Synchronization...
Oct 13 13:35:52 kali systemd[1]: Started systemd-timesyncd.service - Network Time Synchronization.
Oct 13 13:35:53 kali systemd-timesyncd[607]: Network configuration changed, trying to establish connection.
Oct 13 13:35:53 kali systemd-timesyncd[607]: Network configuration changed, trying to establish connection.
Oct 13 13:35:53 kali systemd-timesyncd[607]: Network configuration changed, trying to establish connection.
Oct 13 13:35:53 kali systemd-timesyncd[607]: Network configuration changed, trying to establish connection.
Oct 13 13:36:24 kali systemd-timesyncd[607]: Contacted time server [2606:4700:f1::123]:123 (2.debian.pool.ntp.org).
Oct 13 13:36:24 kali systemd-timesyncd[607]: Initial clock synchronization to Mon 2025-10-13 13:36:24.789417 -03.
                                                                                                                                                                     
┌──(pc㉿kali)-[~]
└─$ sudo systemctl stop systemd-timesyncd
                                                                                                                                                                     
┌──(pc㉿kali)-[~]
└─$ sudo systemctl disable systemd-timesyncd
Removed '/etc/systemd/system/dbus-org.freedesktop.timesync1.service'.
Removed '/etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service'.
                                                                                                                                                                     
┌──(pc㉿kali)-[~]
└─$ sudo ntpdate voleur.htb
2025-10-13 23:49:55.342674 (-0300) +28800.570572 +/- 0.108528 voleur.htb 10.10.11.76 s1 no-leap
CLOCK: time stepped by 28800.570572
                                                                                                                                                                     
┌──(pc㉿kali)-[~]
└─$ impacket-getTGT voleur.htb/'ryan.naylor':'HollowOct31Nyt'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ryan.naylor.ccache
                                                                                                                                                                     
┌──(pc㉿kali)-[~]
└─$ export KRB5CCNAME=/home/pc/Desktop/HTB-writeups/WriteUps.HackTheBox-CTF/Voleur(Windows)/
                                                                                                                                                                     
┌──(pc㉿kali)-[~]
└─$ cd Desktop
                                                                                                                                                                     
┌──(pc㉿kali)-[~/Desktop]
└─$ cd HTB-writeups
                                                                                                                                                                     
┌──(pc㉿kali)-[~/Desktop/HTB-writeups]
└─$ cd WriteUps.HackTheBox-CTF
                                                                                                                                                                     
┌──(pc㉿kali)-[~/Desktop/HTB-writeups/WriteUps.HackTheBox-CTF]
└─$ cd Voleur\(Windows\)      
                                                                                                                                                                     
┌──(pc㉿kali)-[~/Desktop/HTB-writeups/WriteUps.HackTheBox-CTF/Voleur(Windows)]
└─$ nxc ldap voleur.htb -u ryan.naylor -p HollowOct31Nyt -k
LDAP        voleur.htb      389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        voleur.htb      389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
                                                                                                                                                                     
┌──(pc㉿kali)-[~/Desktop/HTB-writeups/WriteUps.HackTheBox-CTF/Voleur(Windows)]
└─$ nxc smb dc.voleur.htb -u ryan.naylor -p HollowOct31Nyt -k
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
                                                                                                                                                                     
┌──(pc㉿kali)-[~/Desktop/HTB-writeups/WriteUps.HackTheBox-CTF/Voleur(Windows)]
└─$ bloodhound-python -u ryan.naylor -p HollowOct31Nyt -k -ns 10.10.11.76 -c All -d voleur.htb --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: voleur.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 12 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.voleur.htb

![Texto alternativo](nombre_del_archivo.png)




