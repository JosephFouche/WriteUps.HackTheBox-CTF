# Primer paso.Escaneo de Puertos con Nmap. 10.10.11.64

![](Nocturnal/nmap.png)
 Se observa Web clasica + ssh

 # HTTP 10.10.11.64:80
 - Correo encontrado : "support@nocturnal.htb"
 
 - tecnologia: PHP, NGINX 1.18.0, Ubuntu
 - No hay sqli en login.php
 - no hay robots.txt
- rutas encontradas:
- 
  /login.php
/register.php
/backups/
/uploads/
/admin.php
/view.php?username=admin2&file=upload1.pdf

Tras el registro (admin2:admin2), podemos subir archivos.

Solo se permiten archivos PDF, DOC, DOCX, XLS, XLSX y ODT.

Solo se verifica la extensión. Pruebe alguna alternativa para subir archivos PHP.

/view.php?username=amanda&file=.pdf

<a href="view.php?username=amanda&file=privacy.odt">privacy.odt</a>

Creds encontradas dentro del archivo odt: 'a[CENSURADO]J'

Amanda es administradora.

Ahora tenemos acceso a /admin.php.

Podemos crear una copia de seguridad con la base de datos.

En la base de datos tenemos el hash de Tobias:

55c8[REDACTED]061d


  cracked in crackstation: slowmotionapocalypse

  users:
        amanda:a[REDACTED]1J
        tobias:s[REDACTED]e



 
