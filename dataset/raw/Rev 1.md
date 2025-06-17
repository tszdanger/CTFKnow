# rev1  
## Description  
Patience is the Key!

## Lookup  
```  
therealbobo@home ijctf/rev1 (master*) $ file main  
main: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically
linked, interpreter /lib/ld-linux.so.2, stripped  
therealbobo@home  
therealbobo@home ijctf/rev1 (master*) $ ./main  
 _________                                    .____                 .__  
/   _____/ ____   ____  __ _________   ____   |    |    ____   ____ |__| ____    
\_____  \_/ __ \_/ ___\|  |  \_  __ \_/ __ \  |    |   /  _ \ / ___\|  |/    \   
/        \  ___/\  \___|  |  /|  | \/\  ___/  |    |__(  <_> ) /_/  >  |   |  \  
/_______  /\___  >\___  >____/ |__|    \___  > |_______ \____/\___  /|__|___|
/  
       \/     \/     \/                   \/          \/    /_____/         \/ 

Login: AAAAAAA  
!!!INTRUDER ALERT!!!  
```

## Solution  
First of all I opened 'main' in radare2:  
```  
therealbobo@home ijctf/rev1 (master*) $ r2 main  
Not loading library because it has already been loaded from somewhere else:
'/usr/lib/radare2/4.3.1/core_ghidra.so'  
-- Radare2 is like violence. If it doesn't solve your problem, you aren't
using enough.  
[0x0804906c]> aa  
[x] Analyze all flags starting with sym. and entry0 (aa)  
[0x0804906c]> afl  
0x0804906c    1 33151        entry0  
0x08049050    1 6            sym.imp.sigaction  
0x08049010    1 6            sym.imp.getline  
0x08049030    1 6            sym.imp.puts  
0x08049020    1 6            sym.imp.printf  
0x08049040    1 6            sym.imp.exit  
[0x0804906c]> s entry0  
[0x0804906c]> pdf  
Do you want to print 6073 lines? (y/N) y  
           ;-- section..text:  
           ;-- eip:  
┌ 33151: entry0 (int32_t arg_4h, int32_t arg_8h);  
│           ; arg int32_t arg_4h @ esp+0x4  
│           ; arg int32_t arg_8h @ esp+0x8  
│           0x0804906c      892540c33f08   mov dword [0x83fc340], esp  ;
[0x83fc340:4]=0 ; [11] -r-x section size 33151 named .text  
│           0x08049072      8b2530c33f08   mov esp, dword [0x83fc330]  ;
[0x83fc330:4]=0x85fc380  
│           0x08049078      8ba42498ffdf.  mov esp, dword [esp - 0x200068]  
│           0x0804907f      8ba42498ffdf.  mov esp, dword [esp - 0x200068]  
│           0x08049086      8ba42498ffdf.  mov esp, dword [esp - 0x200068]  
│           0x0804908d      8ba42498ffdf.  mov esp, dword [esp - 0x200068]  
│           0x08049094      c704240b0000.  mov dword [esp], 0xb        ;
[0xb:4]=-1 ; 11  
│           0x0804909b      c7442404e4c3.  mov dword [arg_4h], 0x85fc3e4 ;
[0x85fc3e4:4]=0x8049060  
│           0x080490a3      c74424080000.  mov dword [arg_8h], 0  
│           0x080490ab      e8a0ffffff     call sym.imp.sigaction      ; int
sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)  
│           0x080490b0      8b2530c33f08   mov esp, dword [0x83fc330]  ;
[0x83fc330:4]=0x85fc380  
│           0x080490b6      8ba42498ffdf.  mov esp, dword [esp - 0x200068]  
│           0x080490bd      8ba42498ffdf.  mov esp, dword [esp - 0x200068]  
│           0x080490c4      8ba42498ffdf.  mov esp, dword [esp - 0x200068]  
│           0x080490cb      c70424040000.  mov dword [esp], 4  
│           0x080490d2      c744240470c4.  mov dword [arg_4h], 0x85fc470 ;
[0x85fc470:4]=0x80490e7  
│           0x080490da      c74424080000.  mov dword [arg_8h], 0  
│           0x080490e2      e869ffffff     call sym.imp.sigaction      ; int
sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)  
│           0x080490e7      8b2530c33f08   mov esp, dword [0x83fc330]  ;
[0x83fc330:4]=0x85fc380  
│           0x080490ed      a15cc33f08     mov eax, dword [0x83fc35c]  ;
[0x83fc35c:4]=1  
│           0x080490f2      8b048550c33f.  mov eax, dword [eax*4 + 0x83fc350]  
│           0x080490f9      c70001000000   mov dword [eax], 1  
│           0x080490ff      c7055cc33f08.  mov dword [0x83fc35c], 0    ;
[0x83fc35c:4]=1  
│           0x08049109      a140c33f08     mov eax, dword [0x83fc340]  ;
[0x83fc340:4]=0  
│           0x0804910e      ba04000000     mov edx, 4  
│           0x08049113      a3f0c11f08     mov dword [0x81fc1f0], eax  ;
[0x81fc1f0:4]=0  
│           0x08049118      8915f4c11f08   mov dword [0x81fc1f4], edx  ;
[0x81fc1f4:4]=0  
│           0x0804911e      b800000000     mov eax, 0  
...  
```  
It appeares to be **movfuscated binary**: _"the M/o/Vfuscator (short 'o',
sounds like "mobfuscator") compiles programs into "mov" instructions, and only
"mov" instructions"_ (https://github.com/xoreaxeaxeax/movfuscator).

At this point there are several ways to solve this challenge:  
* reverse by hand over 6000 lines of assembly (maybe as the last resort)  
* find some tools to simplify the process  
* try a dirty hack

Obviously I tried to search something to simplify my work: I found
"_Demovfuscator_", a cool tool that can recover a movfuscated binary and/or
generate a flowchart of the binary. Cool, right?  
I git cloned it, compiled it and run on the main (_./demov -o patched.bin
main_). Then I opened the patched binary in radare2 but it still was long to
reverse...  
So I tried another way and used _demov_ to take a look at the flow of the
binary.  
```  
./demov -g cfg.dot main  
cat cfg.dot | dot -Tpng > cfg.png  
feh cfg.png  
```

![alt text](https://github.com/therealbobo/ctf-
writeups/raw/master/2020/ijctf/rev1/cfg.png "Program Flow")

I wrote a small gdb python script trying to understand the correct input based
on the number of instruction executed: it didn't work.

At this point I found _perf_ (a linux profiling with performance counters
_https://perf.wiki.kernel.org/index.php/Main_Page_): with the command _stat_
it can retrieve some useful information and in particular with the _-e
instruction:u_ it will output the number of instruction perfomed in user
space... so I tried the dirtiest way: a bash script.

```bash  
readarray -t PRINTABLES < <( echo '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&()+,-./:;<=>?@[\]^_`\{|\}~' |  fold -w1 )

FLAG=''  
while [ "${FLAG: -1}" != '}' ]; do  
	FLAG=$FLAG$(  
		for C in ${PRINTABLES[@]} ; do  
			INSTRUCTIONS=$(echo "$FLAG$C" | perf stat -x: -e instructions:u ./main 2>&1| grep instruction | cut -d: -f1)  
			echo "$INSTRUCTIONS:$C"  
		done | sort -n | head -n1 | cut -d: -f2   
	)  
	echo $FLAG  
done  
```

![alt text](https://github.com/therealbobo/ctf-
writeups/raw/master/2020/ijctf/rev1/demo.gif "demo gif")

And that's the flag :D  
```  
IJCTF{m0v_1s_tur1ng_c0mpl3t3}  
```

Original writeup (https://github.com/therealbobo/ctf-
writeups/tree/master/2020/ijctf/rev1).