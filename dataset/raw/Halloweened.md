# Halloweened

## Point Value  
500

## Challenge Description

My halloween costume was link!

## Internal Description

The challenge has 2 stages of direct input but in reality there are 5 stages
to the challenge for reverse engineers, and the individual stages are all
interconnected.

### Stage 1 - Mach-O parsing init

An entire Mach-O parser is included within the challenge (directly copied from
https://opensource.apple.com/source/dyld/dyld-519.2.1/dyld3/MachOParser.cpp.auto.html)
and it uses this mach-o parser to parse mapped binaries in-memory.

Hidden within a dyld::prepare constructor, (before `main`): it uses this
mach-o parser as-is, and grabs a few key function pointers and walks up their
mapped page to find the system library mapped in memory:  
* dladdr -> libdyld.dylib  
* sleep -> libsystem.dylib  
* mmap -> libsystem\_kern.dylib  
* bootstrap\_look\_up -> libxpc.dylib

### Stage 2 - LCPRNG + Antidebug  
A repeated LCPRNG is called after every operation and every stage of the
challenge. This LCPRNG is also called if we trip any antidebug, to completely
destroy the control flow of the binary. We sprinkle in some antidebug with
this LCPRNG, and have them also run in dyld::prepare.

All scans, checks and business logic in the challenge from this point on use
an obfuscated CRC for comparison.  
The value of the LCPRNG is xor'd into this CRC, breaking CRC comparisons
subsequent stages each time the LCPRNG seed is refreshed.

The only antidebug trick is https://alexomara.com/blog/defeating-anti-debug-
techniques-macos-mach-exception-ports/. This should be fairly easy to defeat
by following that guide, once the competitor understands stage 0 and realizes
we're calling `task_get_exception_ports`.

### Stage 3 - Finding CommonCrypto

The user is now prompted here for a secret passcode. This passcode is appended
to our secret LCPRNG seed, and its correctness determines whether the rest of
the binary will successfully complete.

With libdyld.dylib existing from stage 1, we parse through the binary's symtab
to find the libdyld `_dyld_get_image_header`. Using that, we loop through all
dyld images until we find libCommonCrypto.dylib, using the above method and
the initial LCPRNG value. If a competitor's managed to defeat the exception
ports antidebug technique, they'll be able to pull ou the antidebug\_const
value out of memory here.

Finding the correct passcode should just involve iterating through all library
names in the `dyld_get_image_name` and re-applying this same CRC function to
them.

### Stage 4 - libobjc

Remember how we found libxpc.dylib in Stage 1? This is where it comes in now.
libxpc.dylib has libobjc.dylib linked into it. We do some trickery go from
libxpc.dylib to libobjc.dylib.

I don't expect competitors to actually reverse or understand this trickery -
we reapply stage 3's crc technique, so they should just be able to defeat this
with the same method, except this time also enumerating and applying it to
libobjc's symbols, in order to discover that the secret key is
`__NXReallyFree`.

### Stage 5

The flag and a personalized message is encrypted with AES ECB, with the buffer
being a blob in the binary and the key being `__NXReallyFree`, but done so
through a combination of everything in all of the previous stages.