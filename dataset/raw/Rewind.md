**Description**

> Sometimes you have to look back and replay what has been done right and
> wrong

**Files provided**

- [`rewind.tar.gz`](https://ctf.csaw.io/files/ad0ffb17480563d0658ec831d0881789/rewind.tar.gz) (too large to host)

**Solution**

Once again, after extraction, let's check if the flag is hidden in plain text:

   $ strings disk.* | grep "flag{"  
   while [ true ]; do printf "flag{FAKE_FLAG_IS_ALWAYS_GOOD}" | ./a.out; done  
   while [ true ]; do printf "flag{FAKE_FLAG_IS_ALWAYS_GOOD}" | ./a.out; done  
   flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}  
   ... (repeats)  
   flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}  
   while [ true ]; do printf "flag{FAKE_FLAG_IS_ALWAYS_GOOD}" | ./a.out; done  
   ...  
   while [ true ]; do printf "flag{FAKE_FLAG_IS_ALWAYS_GOOD}" | ./a.out; done  
   flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}  
   ...  
   flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}

And it is there again. I think the organisers overlooked this in both this
challenge and [simple_recovery](#150-forensics--simple_recovery).

What this challenge *should* have been, I assume, is to get QEMU to replay the
given VM snapshot with the given "replay" (which records all user interactions
and non-deterministic I/O).

`flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}`

Original writeup
(https://github.com/Aurel300/empirectf/blob/master/writeups/2018-09-14-CSAW-
CTF-Quals/README.md#200-forensics---rewind).