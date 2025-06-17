# BLOCKchain

Square 2022 Reversing CTF challenge

## Description

Don't worry about how hot your machine's running, the heat won't matter when
we arrive at the heat death of the universe. That said, you may want to figure
out some way to get the flag a little faster than that, considering the CTF
won't last until then :).

## Notes  
This is an optimiziation-style crackme.

Running the challenge will eventually generate the flag sometime between now
and the heat death of the universe.  
There are several time-wasters within the binary that they'll need to
understand and patch out.

The binary itself is a Mach-O, written in Objective C. Notably, this gives
them the ability to recover symbols fairly easily, as I don't make any attempt
to  
mangle objc_msgsend messages. That said, this challenge _is_ written with the
idea that these are exposed, so symbols may or may not make sense. For those
following along from the source, the comments and filenames will probably make
more sense than the actual class or method names.

To make this nontrivial, the problem has the following anti-reversing fun:  
* Several MacOS-specific antidebug tricks are included in the binary. See main.m for all of the antidebug checks. These also get dispatched out and ran continuously in the background in a seperate GCD work queue, abusing lldb's inability to cleanly stepthrough when there's multiple threads simulteanously running.  
* The challenge has its own VM, syscall table, and bytecode format. See vm/fetch.m for the bytecode format and vm/syscall.m for the syscall table.  
* They'll need to patch out the 3 different types of sleep() implementations to spit out the flag.

These methods require seperate methods of disabling antidebug. You can fairly
trivially stub out most of them by using DYLD_INSERT_LIBRARIES (and having
your DYLD_INSERT_LIBRARIES stub include a C constructor that unsets the
environment variable immediately to avoid the dyld_insert environment variable
check).

There's two intended ways of solving this, beyond spending time hard-core
reversing the VM implementation:  
1. Patch out all of the different sleep() implementations, let the challenge print the flag out for you  
2. Reverse enough to understand 1) [calculator hmm<1..n>] methods get run sequentially and 2) the flag_cb_t block exists and a single instance of it is passed down to everything. Run them in a debugger individually.

Original writeup
(https://github.com/square/squarectf/blob/master/2022/data/blockchain.zip).