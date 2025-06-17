### d3bpf

此题是一个 Linux kernel ebpf
利用的入门题。主要参考了[这篇文章](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-
a-love-story)。exp 也有一部分使用了作者的代码。事实上，参考这篇文章就可以完成对本题的利用。非常感谢这篇文章的作者！

This challenge is an introductory question of Linux kernel ebpf exploit. The
main reference is [this artical](https://www.graplsecurity.com/post/kernel-
pwning-with-ebpf-a-love-story). Part of the exp also used the code of the
author. In fact, you can solve this challenge by referring to this article.
Many thanks to the author of this article!

#### 1.Analysis

当 `CONFIG_BPF_JIT_ALWAYS_ON` 生效时（本题的 kernel 就是这样的），ebpf 字节码在载入内核后，会首先通过一个
verifier 的检验。保证不存在危险后，会被 jit 编译为机器指令。然后触发时，就会执行 jit 后的代码。

When `CONFIG_BPF_JIT_ALWAYS_ON` is in effect (which is the case for the kernel
used in this challenge), the ebpf bytecode is loaded into the kernel and
passes a verifier first. After ensuring that there is no danger in the code,
it is then jit compiled into machine code. Then, when triggered, the jited
code will be executed.

因此，如果 verifier 判断出错，就可能通过 ebpf 注入非法代码，实现权限提升。

Therefore, if the verifier judgment is wrong, it is possible to inject illegal
code via ebpf to achieve privilege escalation.

附件中提供了 diff 文件，可以发现添加了一个漏洞

The diff file is included in the attachment, you can find there is a
vulnerability added.

```clike=  
...  
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c  
index 37581919e..8e98d4af5 100644  
--- a/kernel/bpf/verifier.c  
+++ b/kernel/bpf/verifier.c  
@@ -6455,11 +6455,11 @@ static int adjust_scalar_min_max_vals(struct
bpf_verifier_env *env,  
                       scalar_min_max_lsh(dst_reg, &src_reg);  
               break;  
       case BPF_RSH:  
-               if (umax_val >= insn_bitness) {  
-                       /* Shifts greater than 31 or 63 are undefined.  
-                        * This includes shifts by a negative number.  
-                        */  
-                       mark_reg_unknown(env, regs, insn->dst_reg);  
+               if (umin_val >= insn_bitness) {  
+                       if (alu32)  
+                               __mark_reg32_known(dst_reg, 0);  
+                       else  
+                               __mark_reg_known_zero(dst_reg);  
                       break;  
               }  
               if (alu32)  
...  
```

在 X86_64 下，对于 64 位寄存器进行右移操作时，如果操作数大于 63，那么大于 63 的部分会被忽略（也就是只有操作数的低 6
位是有效的）。那么如果我们进行这样一个操作 `BPF_REG_0 >> 64`（且通过了 verifier 的检测），在 ebpf 代码通过 jit
编译后，生成的汇编代码就可能是这样的: `shr rax, 64`，代码执行后，`BPF_REG_0` 应当仍然保持为 1。

Under the X86_64 architecture, if the operand is greater than 63, the part
greater than 63 is ignored (i.e. only the lower 6 bits of the operand are
valid) for a right-shift operation on a 64-bit register. So if we do an
operation like `BPF_REG_0 >> 64` (and it passes the verifier's test), after
the ebpf code is compiled by jit, the resulting assembly code may look like
this: `shr rax, 64`, and after the code is executed, `BPF_REG_0` should still
be 1.

不过这是架构相关的，不同架构可能会有不一样的表现，所以我们可以看到，patch 前的 verifier 在处理该操作时，会把寄存器的范围设置为
unknown。然而 patch 后的 verifier 则会把寄存器直接置为 0，如果我们提前把寄存器置为 1，对它执行右移 64
位的操作，之后就会获得一个运行时值为 1，但是 verifier 确信为 0 的寄存器。

But this is architecture-dependent, and different architectures may behave
differently, so we can see that the pre-patch verifier will set the range of
the register to unknown when it processes the operation. However the post-
patch verifier will set the register directly to 0. If we set the register to
1 in advance and perform a 64-bit right-shift operation on it, we will get a
register that is 1 at runtime, but the verifier is sure it is 0. If we set the
register to 1 in advance, we will get a register with a runtime value of 1,
but the verifier will believe it is 0.

#### 2. exploit

在我们获得了这样的寄存器后，就可以绕过 verifier 对指针运算的范围检测。很容易实现，假设 `EXP_REG` 是一个运行时值为 1，而
verifier 认定为 0 的寄存器，只要将 `EXP_REG` 乘以任意值，与一个指针相加，verifier 会认为将会执行的运算为 `ptr +
0`，实际上则会是 `ptr + arbitrary_val`。

After we obtain such a register, we can bypass the verifier's range detection
for pointer arithmetic. This is easy to achieve. Assuming that `EXP_REG` is a
register with a runtime value of 1 that the verifier determines to be 0, just
multiply `EXP_REG` by arbitrary value, add it to a pointer, and the verifier
will believe that the operation will be `ptr + 0`, but it will actually be
`ptr + arbitrary_val`.

不过，在 ebpf 字节码通过 verifier 的检测后，还会通过 `fixup_bpf_calls` 给字节码添加一些 patch（这个 patch
指，对传入的 ebpf 字节码，在某些存在危险的操作前添加的一些 bpf 指令。添加的字节码将在 jit 编译后一起被加入代码中，作为一种运行期的检测）才会
jit 生成代码，在这里，对于指针（ptr）和标量（scalar）的 BPF_ADD 或 BPF_SUB 运算，会添加这样的 patch

However, after the ebpf bytecode passes the verifier's detection, some patches
(This **patch** refers to some bpf instructions added to the incoming ebpf
bytecode before certain dangerous operations. The added bytecode will be added
to the code after jit compilation as a runtime detection) are added to the
bytecode via `fixup_bpf_calls` before the code is generated by jit, where such
patches are added for BPF_ADD or BPF_SUB operations on pointers (ptr) and
scalars (scalar)

```clike=  
...  
			if (isneg)  
				*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);  
			*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit - 1);  
			*patch++ = BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg);  
			*patch++ = BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg);  
			*patch++ = BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);  
			*patch++ = BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);  
			if (issrc) {  
				*patch++ = BPF_ALU64_REG(BPF_AND, BPF_REG_AX,  
							 off_reg);  
...  
```

这里的 off_reg 指的是将要和 ptr 相加的 scalar。alu_limit 是该指针能够接受的运算的最大值（verifier 对 ptr
的值做跟踪，从而计算出保证 ALU 运算后不会溢出的最大值）。patch 后的代码在执行时，如果 off_reg 的值大于
alu_limit，或者两者的符号相反，那么 off_reg 就会被置 0，可以认为指针运算就不会发生。

The off_reg refers to the scalar that will be added to the ptr. alu_limit is
the maximum value that the pointer can accept for the operation (the verifier
keeps track of the value of the ptr to calculate the maximum value that is
guaranteed not to overflow after the ALU operation). When the code after the
patch is executed, if the value of off_reg is greater than alu_limit, or if
they have opposite signs, then off_reg will be set to 0, and it is assumed
that the pointer operation will not occur.

但是此时我们有一个运行时值为 1，而 verifier 认定为 0 的寄存器，所以其实很容易绕过这个 patch。

But at this point we have a register with a runtime value of 1 and a verifier
identified as 0, so it's actually easy to bypass this patch.

```clike=  
   BPF_MOV64_REG(BPF_REG_0, EXP_REG),  
   BPF_ALU64_IMM(BPF_ADD, OOB_REG, 0x1000),  
   BPF_ALU64_IMM(BPF_MUL, BPF_REG_0, 0x1000 - 1),  
   BPF_ALU64_REG(BPF_SUB, OOB_REG, BPF_REG_0),  
   BPF_ALU64_REG(BPF_SUB, OOB_REG, EXP_REG),  
```

这里 OOB_REG 是一个指向一个 oob_map 头部的指针，EXP_REG 是运行时值为 1，而 verifier 认定为 0 的寄存器，先给
oob_map 加 0x1000，然后通过 EXP_REG 将指针减回 oob_map 头部，verifier 仍然会认为 OOB_MAP 指向的是
`&oob_map + 0x1000`，所以之后对 OOB_MAP 做减法时，patch 的 alu_limit 仍然会是
0x1000，就可以实现向低地址溢出。

Here OOB_REG is a pointer point to the start address of an oob_map, EXP_REG is
a register with a runtime value of 1, and the verifier determines it to be 0.
First add 0x1000 to oob_map, then subtract the pointer back to the start
address of the oob_map by EXP_REG, the verifier will still think that OOB_MAP
is pointing to `&oob_map + 0x1000`, so when subtracting OOB_MAP afterwards,
the alu_limit of patch will still be 0x1000, and overflow to lower address can
be realized.

可以实现 oob 后，最直接的就是我们可以实现 leak，在 oob_map 前面是一个 bpf_map
的元数据，其中存储了一个虚表的地址，该虚表处于内核的 .text 段，load 出来即可实现 leak。

After oob can be achieved, the most direct thing is that we can implement
leak, in front of oob_map is a bpf_map metadata, which stores the address of a
dummy table, the dummy table is in the .text section of the kernel, load out
to achieve leaking.

```clike=  
       BPF_ALU64_IMM(BPF_MUL, EXP_REG, OFFSET_FROM_DATA_TO_PRIVATE_DATA_TOP),  
       BPF_ALU64_REG(BPF_SUB, OOB_REG, EXP_REG),  
       BPF_LDX_MEM(BPF_DW, BPF_REG_0, OOB_REG, 0),  
       BPF_STX_MEM(BPF_DW, STORE_REG, BPF_REG_0, 8),  
       BPF_EXIT_INSN()  
```  
任意地址读可以通过 obj_get_info_by_fd 函数实现。该函数会返回 bpf->id 的值。通过溢出修改 btf 指针即可任意地址读。

Arbitrary address reads can be achieved with the obj_get_info_by_fd function.
This function returns the value of bpf->id. The btf pointer can be modified by
overflow to read at any address.

```clike=  
//kernel/bpf/syscall.c  
	if (map->btf) {  
		info.btf_id = btf_obj_id(map->btf);  
		info.btf_key_type_id = map->btf_key_type_id;  
		info.btf_value_type_id = map->btf_value_type_id;  
	}  
```

通过劫持 oob_map
元数据中的虚表，可以实现任意函数调用。为了劫持虚表，我们需要向内核中写入一些数据，并且需要知道该数据的地址，笔者通过内核的基数树实现从
`init_pid_ns` 开始搜索，搜索到本进程的 task_struct，然后获取 fd_table，然后找出 bpf_map 的地址，读出
`bpf_map->private_data` 的值，由此获得了一个 map 的地址，然后写入 `work_for_cpu_fn` 劫持
`map_get_next_key` 指针，调用此函数，即可实现 `commit_cred(&init_cred)` 实现提权。

By hijacking the virtual table in the oob_map metadata, we can implement
arbitrary function calls. In order to hijack the virtual table, we need to
write some data to the kernel and we need to know the address of that data. I
copyed the kernel's radix tree to search from `init_pid_ns` to the task_struct
of this process, then get the fd_table, then find out the address of bpf_map,
read out the value of `bpf_map-> private_data` to get the address of a map,
then write `work_for_cpu_fn` to hijack the `map_get_next_key` pointer, and
call this function to execute `commit_cred(&init_cred)` to achieve the
privilege escalation.

搜索基数树的代码比较长，这里就不放了，完整的 exp 在[我的 GitHub 仓库](https://github.com/chujDK/my-ctf-
challenges/tree/main/d3bpf)中。

The code for searching the base tree is rather long, so I won't put it here;
the full exp is in [my GitHub repository](https://github.com/chujDK/my-ctf-
challenges/tree/main/d3bpf).

#### 3. more...

正如文章开头所写，本题出题前主要参考了对 CVE-2021-3490 的利用，事实上笔者也是 kernel
利用的初学者，在学习了该利用后才出的这道题。由于新版本的 kernel 增加了对 ALU 运算的
mitigation，所以此利用方法其实已经失效，为了出题选用了一版本较旧的内核，却忘了 patch 掉 CVE-2021-3490，有些师傅使用该 CVE
的公开 exp 改改偏移就打通了，给各位大师傅们带来了十分不好的做题体验，在这里献上笔者最诚挚的歉意。

As written at the beginning of the article, the main reference for this
question was the exploitation of CVE-2021-3490. In fact, I am also a beginner
in kernel exploitation, and only after learning the exploitation did I come up
with this question. As the new version of the kernel has added some
mitigations of ALU operations, so this method of utilization has actually
failed, in order to create a introductory challenge，i chose an older version
of the kernel, but forgot to patch off CVE-2021-3490, some use the public exp
of the CVE to change the offset on the pass, giving you a very bad experience
of doing the problem, I would like to offer my most sincere apologies.

虽然新版本添加了 mitigation，但是对于类似的漏洞，仍然是可利用的，请看 d3bpf-v2。

Although the new version adds mitigation, it is still exploitable for similar
vulnerabilities, please take a glimpse at the challenge d3bpf-v2.

Original writeup (https://cjovi.icu/WP/1604.html).