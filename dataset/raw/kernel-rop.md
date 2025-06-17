The link only contains the exploit source code.

Expected steps of solving the task:  
1) Reverse, notice trivial stack buffer overflow, disable KASLR in run script,
write solution, notice it fails with KASLR  
2) Notice it uses FG-KASLR ( https://lwn.net/Articles/824307/ )  
3) Compare kallsyms from a couple of runs and notice that some symbols are
never randomized, especially ones at the start of the kernel image.  
   Notice that one of the addresses on the stack is also not affected by fine-
grainness.  
4) Find available gadgets in those few available pages.  
5) Notice that there are the ksymtab symbols which are also not affected.  
   Find out that they contain the real symbol offsets.  
   Relevant structure:
https://elixir.bootlin.com/linux/latest/source/include/linux/export.h#L60  
6) Use the gadgets from 4 to read the relevant offsets from 5  
7) Do the standard prepare_kernel_cred, commit_crerds, return to user space

What at least one team did:  
1) Create a script to copy /dev/sda contents to /tmp/flag.  
2) Use the non-randmized gadgets to overwrite the string `/sbin/modprobe` in
kernel memory to point to their script  
3) Trigger the kmod path to have their script be executed  
4) Read flag

Some points:  
1) Using uclibc / musl-libc could be helpful for reducing the binary size  
2) The team with the nicer solution used upx to compress  
3) We would probably add a libc in future kernel pwns

I hope people enjoyed the task.

Original writeup (https://hxp.io/blog/81/hxp-CTF-2020-kernel-rop/).