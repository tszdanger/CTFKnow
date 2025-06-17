### biooosless  
> This challenge is about writing shellcode in the BIOS.

We are given a BIOS image and a Floppy image. The BIOS image runs in QEMU and
our task is to read the flag from the floppy. The floppy we are given contains
a FAT FS and there is one file inside - **dummyflag** with a dummy flag
**OOO{xxx...x}**, assuming that the real flag is on the real floppy in the
server under **flag**.  
What can we do?  
We can give a shellcode which is under 2048 bytes and we are getting injected
somewhere into the BIOS image before its execution.  

First things first, we would want to identify what BIOS it is, and whether we
can find some info on it. When starting the QEMU, it gives us this message:  
> Welcome to (Sea)BIOOOSLESS (version v1337)

Looks like a modified version of the [open source
SeaBIOS](https://github.com/qemu/seabios), which is great because we can
compare it to the sources.  
The python script that runs the QEMU injects our shellcode in the binary where
it can find 2048 'X's. First we need to know what the context is there - time
for IDA.  
I had some problems opening the file in IDA at first, although there is a
**bios_image.py** loader, and I couldn't get the mixture of 32bit code and
16bit code to coexist, so I ended up working with 2 open IDAs, one decompiled
in 32bit mode, and one for 16bit. The 16bit code is not really relevant, so i
worked mostly on the 32bit disassembly.  
For those unfamiliar with how a BIOS works, I'm not going to go too much into
it here, but basically there are 2 modes of execution at this level - [Real
Mode](https://en.wikipedia.org/wiki/Real_mode) and [Protected
Mode](https://en.wikipedia.org/wiki/Protected_mode). In Real Mode the
processor executes 16bit 8086 code and is very limited in resources. Protected
Mode is 32bit code, can utilize much more memory. Both modes allow direct
access to hardware using Ports, Interrupts and MMIO (contrary to Virtual Mode,
where access to hardware is disallowed, and requires asking the OS for that
purpose by using Syscalls or Software Interrupts).  
A x86 CPU starts its execution in Real Mode at the address `F000:FFF0` (See
[Memory Segmentation](https://en.wikipedia.org/wiki/X86_memory_segmentation)),
when the BIOS image is loaded at the address `F000:0000`. So that makes the
entry point in offset `0xFFF0` in the BIOS image we are given. Note that code
in that offset is 16bit.  
So we can open the file in IDA in 16bit loading it at segment `F000` and offset `0000`, or 32bit, loading it at offset `F0000 ((seg << 4) | offset)`.    
The 2048 'X's are at offset `0xF91E4`, which looks like the end of a very very
long function. I converted the 'X's to NOPs (`\x90`) so IDA wouldn't go crazy.
First we should identify the long function and understand our context. There
are some strings being used in the function (like `Welcome to (Sea)BI...`)
that we can match to different functions in the SeaBIOS source code (this one
is probably at **bootsplash.c : enable_vga_console**). It looks like the huge
function is just a mixture of many other (inline?) functions, but we can trace
them back to **post.c : maininit**, which just calls these functions one after
the other. So it makes sense that the compiler chose to inline them to save
space and time. I managed to guess my way at the end of it, before the 'X's,
to find **tcgbios.c : tpm_prepboot** at offset `0xF90CB to 0xF90F7`, then
probably **malloc.c : malloc_prepboot** ending at `0xF91CB` and reaching the
end of **post.c : prepareboot** at `0xF91DC`, where the author placed a small
delay loop and then the shellcode immediately after it.  
So right away we can see that the code is different from the original SeaBIOS
- a lot of stuff is missing... like **make_bios_readonly**, the actual boot
process, and more importantly to us - IVT initialization... But before this,
we need to start debugging the code so we can see more easily what's going on.  
QEMU allows us to stop the CPU from starting execution until GDB is connected
- flags **-s -S** and inside GDB: **target remote 127.0.0.1:1234**. There is
no point to dive into the whole boot process, we just need to see what's
happening when the shellcode is being executed. We can assemble a small
shellcode that simply hangs:  
```  
bits 32  
loop:  
   jmp loop  
```  
Compile with `nasm shellcode.asm -o shellcode.bin` and use `shellcode.bin` as
the input to the python loader. Then we can break after a couple of seconds of
execution (Ctrl+C in GDB) and see what's happening. The first thing that comes
to mind is that we stopped at the address `0x7fbd8a4` and not the expected
`0xF91E4`... This is because the 32bit-only part of the BIOS is relocated to a
higher segment. Some functions still remain in the `0xFXXXX` section, mostly
the functions that are in use by interrupt handlers and common functions from
the initial boot. What's important about this address is that it's
**deterministic** so we can create a `.gdbinit` file and place `hb *0x7fbd8a4`
inside it to always break when we reach the shellcode. Working with a
**.gdbinit** file really saved me a ton of time here on repeating
instructions.  
Ok so we know where we're executed, we know how, and we can get all the
information about the environment. Now we only need to understand what to
write. The goal of the challenge is to read a file from floppy. Going a little
into the code of SeaBIOS, we can see the usage of the floppy drive if we
follow the boot sequence (`startBoot -> int 19h -> handle_19 -> ...`) - it
seems that SeaBIOS is using `INT 13h` to talk to the floppy. Seems pretty easy
usage, [INT 13h is highly documented](https://en.wikipedia.org/wiki/INT_13H).
Let's make sure it's available:  
```  
(gdb) x/100x 0  
0x0:    0x00000000      0x00000000      0x00000000      0x00000000  
0x10:   0x00000000      0x00000000      0x00000000      0x00000000  
0x20:   0xf000e06e      0x00000000      0x00000000      0x00000000  
0x30:   0x00000000      0x00000000      0x00000000      0x00000000  
0x40:   0xc000560e      0x00000000      0x00000000      0x00000000  <- INT 13h
"handler" :(  
```  
Nope... We only have  
* INT 8h - address 0x20 in IVT - Timer - set in the mainint mega-function    
* INT 10h - address 0x40 in IVT - Video - didn't find where its being set  

Now the picture is getting clearer - we need to read the floppy without using
built-in functions at all. In other words, we would have to talk to the
hardware directly.  
At this point I dove deep into SeaBIOS code, trying to understand what is the
first thing that the BIOS is even doing to the floppy. This led me to the
**floppy_setup** function that reads the floppy device type. We can replicate
that code in our shellcode to make sure we're not missing anything and that we
can actually communicate with the floppy.  

`rtc_read(CMOS_FLOPPY_DRIVE_TYPE)` basically translates to  
```  
; outb(CMOS_FLOPPY_DRIVE_TYPE | NMI_DISABLE_BIT, PORT_CMOS_INDEX);  
; type = inb(PORT_CMOS_DATA);

bits 32  
   mov al, 0x90  
   out 0x70, al  
   in al, 0x71  
```  
Tha worked, and I got **AL=0x40** which means `floppyid=0, ftype=4` - we can
found this in the floppy description table in `floppy.c - // 4 - 1.44MB, 3.5"
- 2 heads, 80 tracks, 18 sectors` - makes sense, we were given a 1.44MB image.  
So now that we have a POC of communicating with the floppy, we need to
actually read the data. To do this I basically followed the code that is
getting executed when the BIOS invokes `INT 13h AH=02h` and tried to copy it
into the shellcode - it contains everything that is needed to perform the
first and subsequent reads. The main flow is something like that:  
```  
disk_1302 ->  
   basic_access ->  
       send_disk_op ->  
           # Note that we're in Real Mode, following an interrupt  
           process_op -> process_op_16 ->floppy_process_op ->  
               floppy_read ->  
                   floppy_prep  
                   floppy_dma_cmd  
                   ...  
```  
We don't need to copy **A LOT** of code, so we can just go over the functions
and copy them one by one into a single .c file - ugly, but works :)  
Not all the functions are needed fully. For example, from `basic_access` we
can jump directly to `floppy_read`, etc.  
We can also get rid of different error checking code, such as  
```  
if (count > 128 || count == 0 || sector == 0) {  
   warn_invalid(regs);  
   disk_ret(regs, DISK_RET_EPARAM);  
   return;  
}  
```  
since we know what we're going to read in advance. All the `dprintf`s gotta
go. This:  
```  
ret = floppy_media_sense(drive_gf);  
if (ret)  
   return ret;  
```  
can be omitted, since we know we have a disk in.  
One other thing that may give us trouble is the timers. Finding timer
functions in the relocated code is annoying and including them in the
shellcode is bloated and unnecessary. However, we don't need the code to be
fast and multi-threaded, so we can just convert all the timers into a regular
busy sleep using `RDTSC`. That functionality actually exists in the SeaBIOS
code, it uses two global variables: **ShiftTSC** that I found in `0xFDB82` and
**TimerKHz** (`0xFDB88`):  
```  
static u32 timer_read(void)  
{  
   return rdtscll() >> *(u8*)(0xFDB82);  
}

static u32 timer_calc(u32 msecs)  
{  
   return timer_read() + ((*(u32*)(0xFDB88)) * msecs);  
}

static u32 timer_calc_usec(u32 usecs)  
{  
   u32 cur = timer_read(), khz = (*(u32*)(0xFDB88));  
   if (usecs > 500000)  
       return cur + DIV_ROUND_UP(usecs, 1000) * khz;  
   return cur + DIV_ROUND_UP(usecs * khz, 1000);  
}  
```  
Another annoyance that I found was `floppy_wait_irq` - we wait until we're
interrupted by the floppy and the interrupt handler sets a global flag in
memory. But we don't REALLY need to wait for the interrupt - we're only
waiting for the floppy to finish processing our request, so we can assume that
it will complete successfully, and for the waiting time, 1 millisecond should
suffice :). So that call can be replaced with `msleep(1);`  
The call to `getDrive(EXTTYPE_FLOPPY, extdrive)` can be omitted as well, since
we already checked the device type and we can populate it by ourselves:  
```  
drive_fl.cntl_id = 0; //floppyid;  
drive_fl.type = 0x10; //DTYPE_FLOPPY;  
drive_fl.blksize = 512; //DISK_SECTOR_SIZE;  
drive_fl.floppy_type = 4; //ftype;  
drive_fl.sectors = (u64)-1;

// 4 - 1.44MB, 3.5" - 2 heads, 80 tracks, 18 sectors

drive_fl.lchs.head = 2;  
drive_fl.lchs.cylinder = 80;  
drive_fl.lchs.sector = 18;  
```  
The code uses some MACROs such as `GET_FARVAR`, `GET_BDA` etc. These can be
copied under the assumption that `MODESEGMENT=0` since we are running in
Protected Mode.  
Last thing, we need a global variable `FLOPPY_DOR_VAL`. We can just choose a
random address for it, we know that `0xc0000 - 0x100000` is mapped, so I
randomly chose `0xc9ff0` (was doing some tests in `0xca000`)  
```  
#define FLOPPY_DOR_VAL (*(u32*)(0xc9ff0))  
```  
Compiling the code was a bit annoying, but after some trial and error I
arrived at these flags:  
```  
gcc -m32 -Os -fomit-frame-pointer -Wno-builtin-declaration-mismatch -fno-
stack-protector -fno-asynchronous-unwind-tables -march=i386 -c read_floppy.c
-o read_floppy.o  
```  
And finally, after some tweaking I managed to get the code to work and read
the first sector into the `0x7c0` segment (it's the segment being used in the
boot sequence):  
```  
struct bregs br;

memset(&br, 0, sizeof(br));  
br.flags = F_IF;  
br.dl = 0;      // drive  
br.es = 0x7c0;  // segment  
br.ah = 2;      // read command  
br.al = 1;      // sectors to read  
br.cl = 1;      // sector  
```  
Note that if this is successful, the memory will be written in address
`0x7c00` (segment << 4).  
Now the only thing we need is to find the flag! We can parse the FAT
partition, but we don't really need to, we can read multiple sectors and
search for "OOO{". For some reason I missed the part that you can read
multiple sectors at once, so I just made a loop that reads a single sector to
address `0x7c00` and scans it for the beginning of the flag.  
Once the flag is found we only need to display it on the screen and we're
done! The simplest solution, as I imagined it, would be to use the same
function that the BIOS uses to display the "Welcome" string, but for some
reason I didn't manage to get it to work, something would always break in the
interrupt handler. I figured maybe the BIOS changed the VGA mode, so I decided
to write directly to the VGA buffer (at address `0xb8000`) and surprisingly
enough, this worked like a charm!  
```  
int i=0;  
while(*flag){  
   *(u16*)(0xb8000 + i) = (0x0F00) | *(flag++);  
   i += 2;  
}  
```  
Just a reminder, writing a byte to the VGA buffer takes 2 bytes, where the MSB
is the color scheme. 0x0F is "White on Black".  
That's it! I was too lazy to write a python script that will communicate with
the server and display the output, so just pasted the base64 encoded
shellcode, and after a second:  
```  
OOO{dont_make_fun_of_noobs_that_cant_read_from_floppies_it_aint_that_easy}  
```  
This was super fun, I remembered some vagua details about 8086 execution and
Real/Proteted Modes, and this challenge was a good reminder and a good source
of knowledge of things that I would have probably never seen otherwise :)

Original writeup (https://github.com/amelkiy/write-
ups/tree/master/OOODefconQual-2020/biooosless).