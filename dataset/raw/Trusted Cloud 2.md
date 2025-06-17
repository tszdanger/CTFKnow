The disk image decrypted in Part 1 contains 4 files in `/home/passwords`:  
* `decrypt_flag.sh` with the command `openssl pkeyutl -engine tpm2tss -keyform engine -inkey key.pem -decrypt -in passwords_flag.txt.enc`  
* `pubkey.pem` that seems to be an ordinary RSA-2048 public key  
* `passwords_flag.txt.enc` with 256 bytes of garbage, presumably encrypted with the key above  
* the following `key.pem`:  
```  
-----BEGIN TSS2 PRIVATE KEY-----  
MIICEwYGZ4EFCgEDoAMBAQACBQCBAAAABIIBGAEWAAEACwAGBHIAAAAQABAIAAAB  
AAEBAL3CUfIQc81ZcnbTVc5m+WXwavOUuhXVMGGh2Wc0YCcucCGfwGLUERZYWzQK  
Dxng2Aq0Fa/BKg0pdLxZqEgXjlaCrXLwiQR6ocxL1KxrRuldOM83A5FtgpcNEtDe  
xn5f9j3qbvMOD8k9NKvdmgvqLMb52iaLdAkJA2pec+72nGP14J6lJoB/6+pnPfnp  
OY6/YggAiGf1FRF/JXN7pEydCnH0Mdq3g4csv2B2VwjkQTHz5UkOefOhT3kGLAku  
XMVdxZ8U6YgcC3LzyB5QjDFPBPDAAxYYgRGoqlQav0D3Do3hZwrOq/4vIC5dU4Kx  
yO5Svy7ITNepbf8PhGXPl7kdvXcEgeAA3gAg8u9WIVariG4CxvgurtbIj0u7HXk+  
52f1uITfHtlTxDAAEKrPxEQTSqH5Ib1cFUYwSdyZmsBzKdcuQCDs/mT4mr7/WQmn  
vN1cN1XbuLuiK3SspiQ+v/aFk9472o0pyV7RY9u60zQvsKXhYf6vJNjFYL02QP8R  
FoCUfCGZKGtnSnzcZpbEGDnzy2+UxxVUjEc0YCDPgZYdgyHAHB2NeZhw6AITQH5O  
P2w81IPTdnrEIl3CCd9IoEsyIoDPLJcJwc4/dCKDCVd4fR+hXP8R5++9CVd1iOFY  
7A+mvQiKsw==  
-----END TSS2 PRIVATE KEY-----  
```

[https://lapo.it/asn1js/](https://lapo.it/asn1js/) decodes `key.pem` into a
sequence of 5 items:  
* OBJECT IDENTIFIER 2.23.133.10.1.3 (presumably just an identifier of "TSS2 PRIVATE KEY")  
* BOOLEAN false  
* INTEGER 0x81000000  
* 280-byte string with mostly-zeroes header and some binary data  
 that upon a closer investigation turns out to be the same as modulus in
`pubkey.pem`  
* 224-byte string of the form `00DE0020`(32 bytes of binary data)`0010`(more binary data)

Usual RSA private keys contain a private exponent and all prime divisors of
the modulus;  
these are too big to fit in unknown 224-byte field. On the other hand,  
224 bytes are too much for a simple identifier of something stored inside TPM.

The provided TPM image is launched by simple shell script that runs `qemu-
system-riscv64`  
with exposing host's `/dev/urandom` to the guest and guest's port 2321 to the
host.

It is time to launch everything locally and see how it fits together.  
TPM image boots without problems. However, `decrypt_flag.sh` cannot find
tpm2tss engine.  
Well, it is relatively easy to find
[https://github.com/tpm2-software/tpm2-tss-
engine/](https://github.com/tpm2-software/tpm2-tss-engine/)  
and underlying library
[https://github.com/tpm2-software/tpm2-tss](https://github.com/tpm2-software/tpm2-tss)
. They don't seem  
to reach into Debian package distributions (yet?), but at least have INSTALL  
instructions and basic usage examples.

[...pause...](https://xkcd.com/303/)

Compiled binaries appear... but they refuse to work with the launched TPM
image,  
saying something about inability to connect to port 2322. After some digging
in sources,  
I have noticed that TCP connections can be handled by tcti-mssim and tcti-
swtpm,  
and both of those use two sockets on two ports; while the first connection to
port 2321  
succeeds, the second connection fails. If TPM image does not expose the second
port,  
then maybe the second connection is not so important, so I have decided to
insert  
`return TSS2_RC_SUCCESS;` to the beginning of `tcti_control_command` in tcti-
swtpm.c  
and watch for problems.

...recompiling and reinstalling...

This time, the usage example works, successfully generates a private key  
and encrypts/decrypts test data. The generated key looks quite like `key.pem`,  
but not without differences:  
* the second item of the sequence is BOOLEAN true instead of false  
* the third item is INTEGER 0x40000001 instead of 0x81000000  
* binary data is different, but it is expected

`decrypt_flag.sh` asks for a password. A random string does not work.  
Well, that was not surprising.

Structure of the key can be found by grepping "TSS2 PRIVATE KEY" in sources:  
[https://github.com/tpm2-software/tpm2-tss-engine/blob/master/src/tpm2-tss-
engine-common.c#L46](https://github.com/tpm2-software/tpm2-tss-
engine/blob/master/src/tpm2-tss-engine-common.c#L46)  
The second field is `emptyAuth`, the third field is `parent`.

Let's try to change the original key to `emptyAuth=TRUE` (byte 0x00 ->
0xFF)...  
now openssl doesn't ask for password, but doesn't work either. Well, it was
worth trying anyway.

`tcpdump` for port 2321 shows that `openssl pkeyutl -decrypt` just sends
binary data as is  
using command code `TPM2_CC_Load`, together with plaintext password if
provided.  
It seems that tpm2-tss library won't provide much more information,  
so it is now time to look more closely into TPM image.

`binwalk -e` over the provided kernel extracts zlib-compressed data `60C7C0`
that  
turns out to be cpio archive of initrd (good, I was already mentally preparing  
to disassemble the kernel and wondering why this isn't in Reverse category)  
with the following /init:  
```  
#!/bin/busybox sh  
busybox mkdir -p /dev /proc /sys  
busybox mount -t devtmpfs dev /dev  
busybox mount -t proc proc /proc  
busybox mount -t sysfs sys /sys

if ! (busybox ip route show | busybox grep 'dev eth0') ; then  
   echo -e "\033[31;1mERROR: Ethernet interface not configured"  
   set -x  
   busybox ls -l /sys/class/net  
   busybox ip link  
   busybox ip addr  
   busybox poweroff -f  
fi

echo "Starting TPM"  
echo "0x$( (busybox id && busybox ls -1 / /tpm) |busybox sha256sum | busybox cut -d\  -f1)" > /...  
swtpm socket --tpm2 --server port=2321,bindaddr=0.0.0.0 --flags not-need-
init,startup-clear --tpmstate dir=/tpm --key
file=/...,format=hex,mode=aes-256-cbc,remove=true  
busybox poweroff -f  
```

Initrd image also contains executable `/bin/swtpm`, libraries
`/lib/libtpms.so.0` and `/lib/swtpm/libswtpm_libtpms.so.0`,  
and an encrypted file `/tpm/tpm2-00.permall`.

Reconnaissance shows the following:  
* swtpm is open-source [https://github.com/stefanberger/swtpm](https://github.com/stefanberger/swtpm)  
* swtpm handles TCP stuff, but delegates the actual work to libtpms  
* libtpms is also open-source [https://github.com/stefanberger/libtpms](https://github.com/stefanberger/libtpms)  
* tpm2 part of libtpms closely follows the reference implementation by TCG:  
 [https://trustedcomputinggroup.org/resource/tpm-library-
specification/](https://trustedcomputinggroup.org/resource/tpm-library-
specification/)  
* the reference implementation comes with 4-volume 30-megabyte specification  
* given the size of the specification, it is unclear which way is simpler  
 to grasp some particular aspect: reading the spec or following the code.  
 I have mostly used the second way

Now, getting inside swtpm is required. There are two possible directions.  
The first way is launching qemu with built-in gdb server `-S -s` and  
using a specific version of gdb to debug RISC-V64 code. The second way  
is compiling, configuring and installing swtpm and libtpms, then grabbing  
all settings from initrd image (the master key is
`33f5cd9fca9372b7a7710473ea72993716bad14cb3e04f000de0a1b5157cf3a1`,  
by the way) and using standard native debugger, debug printing or whatever.  
In my experience, compiling a random bulk of C or C++ code is a lottery  
where result can be anything from "it just builds and runs without any  
problems" to "you should find a dozen of dependencies and dependencies  
of dependencies, you should use two-year-old version for some of them  
to match the age of initial code, you should also fix some compilation  
errors because the compiler has also advanced in those two years...  
and just hope that the compiler won't [silently break the code in
runtime](https://www.imperialviolet.org/2016/06/26/nonnull.html)  
because it contradicts some obscure corner of the standard". So I have chosen  
to go the first way. In principle, existing TPM image can be somehow modified,  
but in the end, I have not found any evidence of that, so the second way  
would probably work as well.

Common `gdb-multiarch` refuses to deal with 64-bit RISC-V, so [a special
version](https://github.com/sifive/freedom-tools/releases) is needed.  
However, `objdump` disassembles usermode parts just fine, including  
all the symbols (I'm not sure whether this comes out-of-box or due to some  
installed package) and needs just a little push for the kernel  
(`objdump --target binary --architecture riscv:v64 --disassemble-all vmtpm-
kernel`).

GDB server of qemu provides a kernel debugger, so the first step after  
letting the emulated system to fully boot is getting into usermode  
in the context of the right process. Internet says that sysexit instruction  
in RISC-V64 is named SRET; objdump-ing the kernel finds it at offset `0x1bea`.  
`b *0xffffffff80001bea; c` shows that this is constantly executed by the
kernel-mode  
code as well; Internet says that return address for SRET is stored in `$sepc`
register,  
so `b *0xffffffff80001bea if $sepc>0` gets rid of false positives and breaks
only  
when openssl tries to connect to the socket (`stepi` leads to `poll` from libc  
in the context of swtpm process that is in turn called from `mainLoop`  
of libswtpm_libtpms). From there, it is relatively straightforward  
process of matching source code and disassembled code with symbols while
tracing  
with `stepi`, `b *<address>` and `advance *<address>`.

The path to `TPM2_CC_Load` handler looks like this:  
* `mainLoop` from libswtpm_libtpms.so eventually calls `TPMLIB_Process` from libtpms.so:  
[mainloop.c#L292](https://github.com/stefanberger/swtpm/blob/50670dca124ff4ac7a5e478beebd4861641b8a60/src/swtpm/mainloop.c#L292)  
* `TPMLIB_Process` jumps to version-specific handler: [tpm_library.c#L164](https://github.com/stefanberger/libtpms/blob/cd8025fa6fbf141ef431595efc2a5d416244d3c3/src/tpm_library.c#L164), TPM2 corresponds to `TPM2_Process`  
* `TPM2_Process` calls `_rpc__Send_Command`: [tpm_tpm2_interface.c#L219](https://github.com/stefanberger/libtpms/blob/cd8025fa6fbf141ef431595efc2a5d416244d3c3/src/tpm_tpm2_interface.c#L219)  
* `_rpc__Send_Command` calls `_plat__RunCommand`: [TPMCmdp.c#L245](https://github.com/stefanberger/libtpms/blob/cd8025fa6fbf141ef431595efc2a5d416244d3c3/src/tpm2/TPMCmdp.c#L245)  
* `_plat__RunCommand` calls `ExecuteCommand`: [RunCommand.c#L95](https://github.com/stefanberger/libtpms/blob/cd8025fa6fbf141ef431595efc2a5d416244d3c3/src/tpm2/RunCommand.c#L95)  
* `ExecuteCommand` finally starts parsing and processing the command: [ExecCommand.c#L153](https://github.com/stefanberger/libtpms/blob/cd8025fa6fbf141ef431595efc2a5d416244d3c3/src/tpm2/ExecCommand.c#L153)

From there on, there are two areas of potential interest: what happens to the
password  
and what happens to the private key argument. These follow different code
paths.

The private key for TPM RSA turns out (`CommandDispatcher` -> `TPM2_Load`) to
be authenticated and encrypted  
(`TPM2_Load` -> `PrivateToSensitive`) divisor of the modulus (`TPM2_Load` ->
`ObjectLoad` -> `CryptRsaLoadPrivateExponent`).  
That explains why it is smaller than the modulus - for standard two-prime
keys,  
one divisor combined with the modulus is enough to calculate everything else.

The password is checked via the chain `ExecuteCommand` -> `ParseSessionBuffer`
-> `CheckAuthSession` -> `CheckPWAuthSession` -> `MemoryEqual2B`,  
in the end it just compares the provided password with somehow-calculated
value.  
Aha! I have a debugger, so I can just read the correct value without bothering  
how exactly it is fetched/calculated, using a breakpoint in corresponding
location.  
All intermediate functions between `ParseSessionBuffer` and `MemoryEqual2B`
turn out  
to be inlined, the actual call instruction `jal ra,MemoryEqual2B` is at
`0x58a84`  
relative to base of libtpms (it is different each time due to ASLR, but  
should have been found during previous tracing) and the conditional branch
`beqz`  
is at `0x58a88`.

The correct value turns out to be 32-byte binary instead of a text,  
`7740ba0e627b5d6ba2a0acf0175981504350d9d9481963d1e0bba39ce6bc773c`. Then,
there are  
two equally valid choices:  
* skip the branch in gdb (`set $pc = $pc+4` when `$pc` points to `0x58a88`)  
 to bypass the check; the further decryption succeeds even with a wrong
password;  
* write those bytes in a binary file and provide `-passin file:passwordhash` to openssl.

Further investigation reveals that if the password is too long, it is hashed  
by tpm2-tss library inside openssl:
[https://github.com/tpm2-software/tpm2-tss/blob/e900ef04ccec7e1daab9542124339e225800b7a3/src/tss2-esys/esys_iutil.c#L1567](https://github.com/tpm2-software/tpm2-tss/blob/e900ef04ccec7e1daab9542124339e225800b7a3/src/tss2-esys/esys_iutil.c#L1567)
.  
So the actual password remains a mystery (or maybe it actually was binary from
the beginning?),  
but it is not needed for the flag. The flag is given by openssl output  
with bypassed or provided password:
`CTF{My_super_strong_P455w0rd_is_now_yours!}`.