# **HTB Sherlock - PhantomRing**

This one was a step up for me. My other write-ups are log analysis, so pulling apart a malware binary was new ground. It took me a long time and I leaned on online resources and the hints, but I wanted to understand what this thing actually does. This was completed a number of weeks ago, the writeup was done at the same time.

### Question 1: What is the SHA256 hash of the binary?

- Answer: 2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5

Started simple. Opened a terminal in the folder with the binary and ran 'sha256sum agent'. Then 'file agent' to see what I was dealing with:

```
agent: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1f617f2ea259a7ec724d7bbc01627982dc2f0495, for GNU/Linux 3.2.0, not stripped
```

So it's a 64-bit Linux program. "Not stripped" means the function names are still in there, which helped later in Ghidra.

### Question 2: What is the IP address hardcoded in the binary for C2 communication?

- Answer: 192.168.56.1

Tried FLOSS for pulling out strings, so I set it up in a virtual environment:

```
python3 -m venv ~/floss-env
source ~/floss-env/bin/activate
pip install flare-floss
```

Then ran it on the binary:

```
floss agent
INFO: floss: extracting static strings
ERROR: floss: failed to analyze sample: FLOSS currently supports the following formats for string decoding and stackstrings: PE
You can analyze shellcode using the --format sc32|sc64 switch. See the help (-h) for more information.
```

It didn't like the file. The error mentioned shellcode, so I guessed the file must be shellcode and tried again with:

```
floss --format sc64 agent
```

That worked, and the IP was right there in the output.

### Question 3: Find the C2 port.

- Answer: 4445

This is where it got harder for me. The strings gave me the C2 IP (192.168.56.1) and a few networking clues, but I had to go into Ghidra for the port. I found where the IP was referenced and followed it back to the connection code, where the port shows up as a hardcoded argument.

### Question 4: How many seconds does the agent wait before attempting to reconnect after a failed connection?

- Answer: 120

Stayed in Ghidra and looked for a sleep call near the connection code:

```
001043e7 bf 78 00        MOV        EDI,0x78
         00 00
001043ec e8 ef d0        CALL       <EXTERNAL>::sleep        uint sleep(uint __seconds)
         ff ff
```

The value goes into EDI just before sleep is called. 0x78 is hex, so that's 120 seconds.

### Question 5: How many different commands does the agent support? (excluding invalid commands)

- Answer: 11

Because the binary isn't stripped, the function names are still there. I counted 11 CMD entries in Ghidra's Symbol Tree.

### Question 6: What Linux kernel interface does this malware abuse to evade EDR syscall monitoring?

- Answer: io_uring

Spotted a whole load of io_uring functions:

```
io_uring_queue_init
io_uring_queue_exit
io_uring_submit
__io_uring_get_cqe
io_uring_get_sqe
io_uring_prep_connect
io_uring_prep_send
io_uring_prep_recv
io_uring_prep_openat
io_uring_prep_close
io_uring_prep_read
io_uring_prep_write
io_uring_prep_unlinkat
```

I hadn't come across io_uring before, so I read up on it. From what I understand, it lets a program queue up file and network operations in buffers it shares with the kernel, instead of making a separate syscall for each one. So security tools watching for the usual syscalls can miss what it's doing.

### Question 7: What file does the agent read to enumerate logged-in users?

- Answer: /var/run/utmp

At this point I went back to basics and ran strings, which turned out to answer most of the remaining questions:

```
strings agent
```

```
/var/run/utmp
Error reading /var/run/utmp
Logged users:
```

/var/run/utmp is a binary file (not a folder) that keeps track of who's logged in.

### Question 8: What directory does the agent scan when searching for SUID binaries for privilege escalation?

- Answer: /usr/bin

Same strings output:

```
/usr/bin
Failed to open /usr/bin
Potential SUID binaries:
/usr/bin/%s
```

SUID binaries run with their owner's permissions, often root, which is why they're a common route to privilege escalation. The agent goes looking for them in /usr/bin.

### Question 9: What string does the agent search for in /proc/[pid]/maps to identify security tools using eBPF?

- Answer: anon_inode:bpf-map

Also in the strings:

```
/proc/%s/maps
anon_inode:bpf-map
[+] Killed PID using BPF: %d
[-] Failed to kill PID %d: %s
[*] No processes with BPF map found
```

This one made me curious. From what I read, a lot of Linux security tools use eBPF to watch the system, so the agent checks each process's memory maps for a BPF map and kills anything it finds. It's going after the tools that would catch it.

### Question 10: What is the full path of the first tracing file the agent attempts to disable?

- Answer: /sys/kernel/debug/tracing/tracing_on

Strings again:

```
Agent disconnecting and exiting
/sys/kernel/debug/tracing/tracing_on
/sys/kernel/debug/tracing/set_event
/sys/kernel/debug/tracing/current_tracer
[*] Tracing disabled: %s
```

Same idea as the last one. It tries to switch off the kernel's built-in tracing, which would blind anything relying on it.

### Question 11: What procfs path does the agent read to find its own executable location before self-destruction?

- Answer: /proc/self/exe

Spotted here:

```
Agent will self-destruct
/proc/self/exe
Unlink failed: %s
Agent disconnecting and exiting
```

/proc/self/exe points to the running program's own file, so the agent can find itself and delete itself. The "Unlink failed" line is the delete step.

### Question 12: What command string is compared by the agent to trigger deletion of its own binary?

- Answer: sdestruct

The strings list out the commands:

```
get
recv
users
netstat
kick
privesc
sdestruct
killbpf
exit
[*] 404 Command not found [*]
```

Process of elimination, it's sdestruct.
