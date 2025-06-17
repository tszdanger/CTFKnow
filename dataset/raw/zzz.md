## Description of the challenge

3z

Author: NoobHacker

## Solution

This is obviously a z3 challenge. We can open the binary in Ghidra and see
various constraints. Instead of solving them manually, let's just try some
angr magic. I won't even attempt to add the constraints. I'll just add the
beginning of the flag.

```py  
#!/usr/bin/env python3  
import angr  
import claripy  
import sys

def is_successful(state):  
   #Successful print  
   stdout_output = state.posix.dumps(sys.stdout.fileno())  
   return b'You got it!' in stdout_output

def should_abort(state):  
   #Avoid this print  
   stdout_output = state.posix.dumps(sys.stdout.fileno())  
   return b"That's wrong!" in stdout_output

proj = angr.Project('./chall')

flag = claripy.BVS("flag", 8 * 30)

state = proj.factory.entry_state(stdin = flag)

state.solver.add(flag.get_byte(0) == ord('n'))  
state.solver.add(flag.get_byte(1) == ord('0'))  
state.solver.add(flag.get_byte(2) == ord('0'))  
state.solver.add(flag.get_byte(3) == ord('b'))  
state.solver.add(flag.get_byte(4) == ord('z'))  
state.solver.add(flag.get_byte(5) == ord('{'))

for i in range(6, 30):  
   state.solver.add(flag.get_byte(i) >= 33)  
   state.solver.add(flag.get_byte(i) <= 125)

sm = proj.factory.simulation_manager(state)

sm.explore(find=is_successful, avoid=should_abort)

if sm.found:  
   sol = sm.found[0]  
   print(sol.posix.dumps(sys.stdin.fileno()))  
else:  
   print("no sol")  
```  
We run the script:  
```  
$ ./solve.py  
WARNING  | 2023-06-23 01:35:39,568 | angr.simos.simos | stdin is constrained to 30 bytes (has_end=True). If you are only providing the first 30 bytes instead of the entire stdin, please use stdin=SimFileStream(name='stdin', content=your_first_n_bytes, has_end=False).  
b'n00bz{ZzZ_zZZ_zZz_ZZz_zzZ_Zzz}'  
```

It's _that_ easy!  

Original writeup (https://dothidden.xyz/n00bzctf_2023/zzz/).# zzz.py

```py

from z3 import *

s = Solver()

a = [BitVec(f'a{i}', 64) for i in range(35)]

l = [ 0x76, 0x26, 0x2f, 0xfd, 0x91, 0xec, 0x37, 0xde, 0x66, 0x70, 0x1e, 0x8a,
0x5a, 0x46, 0xa8, 0x63, 0xb7, 0xf0, 0xa3, 0x24, 0x61, 0xc1, 0x2b, 0xa0, 0xd6,
0x50, 0x4f, 0x92, 0x9b, 0x52, 0xcb, 0xe8, 0xed, 0x4b, 0xf1, 0x4d, 0x01, 0x8e,
0x9c, 0xca, 0x5f, 0x34, 0x64, 0x97, 0x23, 0xc7, 0xee, 0x18, 0x6a, 0x72, 0x3c,
0xf6, 0x32, 0xd3, 0x6e, 0x08, 0x3b, 0xb3, 0xb8, 0xab, 0xf4, 0x29, 0xc2, 0x67,
0x1f, 0xe2, 0x59, 0xad, 0xe5, 0x81, 0xbe, 0x7b, 0x9f, 0xa1, 0x10, 0x90, 0xfc,
0xb2, 0xff, 0x41, 0x33, 0xa2, 0x42, 0xcc, 0x69, 0x62, 0x68, 0x22, 0xb9, 0x96,
0x71, 0xe6, 0x21, 0x40, 0x3f, 0xdc, 0x93, 0xbb, 0x44, 0x7c, 0xd4, 0xcf, 0xe3,
0xf7, 0x78, 0x31, 0x85, 0x79, 0x95, 0x27, 0xda, 0xf5, 0x4e, 0x7f, 0x20, 0xa6,
0xe0, 0xe1, 0x7e, 0x3d, 0xd5, 0xaf, 0x8d, 0xfa, 0xb1, 0xe9, 0xaa, 0x1b, 0x49,
0x58, 0xe7, 0x0d, 0x47, 0xbc, 0xe4, 0x04, 0x17, 0xb0, 0xc8, 0x4a, 0x02, 0x99,
0x6d, 0xdf, 0xdd, 0x65, 0x09, 0x7d, 0x6f, 0x0b, 0xc4, 0x19, 0x1d, 0xfe, 0xd7,
0x5b, 0x06, 0xa4, 0xf3, 0xa9, 0x2d, 0xc0, 0x9a, 0x53, 0x89, 0x16, 0xa5, 0xbd,
0x74, 0x2a, 0x05, 0xc5, 0x6b, 0xd9, 0xf8, 0xfb, 0x39, 0x2c, 0x5d, 0xd0, 0x3e,
0xbf, 0x03, 0x7a, 0x94, 0xc9, 0x1c, 0x25, 0x5e, 0x11, 0xf2, 0x8f, 0x5c, 0x14,
0xeb, 0x45, 0x9d, 0x38, 0x86, 0x98, 0x1a, 0xb4, 0x28, 0x51, 0x0c, 0x13, 0xac,
0x0a, 0x35, 0x82, 0xb6, 0x8b, 0x30, 0x75, 0xd8, 0x00, 0xef, 0xba, 0xc3, 0xae,
0xf9, 0x9e, 0x4c, 0x0e, 0x77, 0x57, 0xd1, 0x6c, 0xdb, 0x3a, 0x07, 0xcd, 0x54,
0x8c, 0x15, 0x88, 0x2e, 0xd2, 0xa7, 0xea, 0x55, 0xc6, 0xce, 0xb5, 0x43, 0x0f,
0x56, 0x60, 0x83, 0x80, 0x84, 0x36, 0x87, 0x12, 0x48, 0x73 ]

for i in range(35):  
   s.add(Or(a[i] == ord('-'), And(a[i] >= ord('A'), a[i] <= ord('Z')),
And(a[i] >= ord('a'), a[i] <= ord('z')), And(a[i] >= ord('0'), a[i] <=
ord('9'))))

s.add(a[26] + a[24] + a[15] + a[13] + a[4] + a[2] + a[0] + a[28] == 486)  
s.add(a[1] * a[0] - a[4] + a[12] * a[13] - a[16] + a[24] * a[25] - a[28] ==
13713)  
s.add(a[27] * a[14] * a[3] - a[15] * a[2] * a[25] == -6256)  
s.add((a[1] - a[3]) * a[4] == 48)  
s.add((8 * a[13] - 4 * a[15]) * a[14] == 20604)  
s.add((4 * a[28] - 4 * a[0]) * a[27] == -5616)

for i in range(35):  
   v5 = If(And(i%12 <= 4, (Or(Or(ord('Z') < a[i], a[i] < ord('0')),
And(ord('9') < a[i], a[i] < ord('A'))))), 0, 1)

v1 = If(And(a[4] - a[3] - a[2] - a[1] + a[0] * a[0] == 6744, a[16] - a[15] -
a[14] - a[13] + a[12] * a[12] == 2405, a[28] - a[27] - a[26] - a[25] + a[24] *
a[24] == 4107), 1, 0)  
v2 = If(And(a[14] <= 57, (a[14] + a[24]) * (a[28] - a[1]) == -1508), 1, 0)

s.add(v1 == 1)  
s.add(v2 == 1)  
s.add(v5 == 1)

for i in range(35):  
   if i not in [5, 11, 17, 23, 29]:  
       s.add(a[i] != ord('-'))

s.add(a[5] == ord('-'))  
s.add(a[11] == ord('-'))  
s.add(a[17] == ord('-'))  
s.add(a[23] == ord('-'))  
s.add(a[29] == ord('-'))

ll = [0] * 15

xx = [ 6, 7, 8, 9, 10, 18, 19, 20, 21, 22, 30, 31, 32, 33, 34 ]

vv5 = 0  
vv6 = 0  
for i in range(15):  
   vv5 = (vv5 + 1) % 256  
   vv6 = (vv6 + (l[vv5] & 0xff)) % 256  
   v4 = l[vv5] & 0xff  
   l[vv5] = l[vv6] & 0xff  
   l[vv6] = v4  
   a[xx[i]] ^= (l[((l[vv5] & 0xff) + (l[vv6] & 0xff)) & 0xff] & 0xff)

vv8 = 0  
a2 = 15  
gg = []

while vv8 < a2:  
   vv7 = 0  
   vv3 = 0  
   vv12 = [0] * 4  
   while True:  
       if vv7 <= 2 and vv8 < a2:  
           vv3 = (vv3 << 8) | (a[xx[vv8]] & 0xff)  
           vv8 += 1  
           vv7 += 1  
       else:  
           break  
   vv4 = vv3 << (8 * (3 - vv7))  
   for i in range(4):  
       if vv7 >= i:  
           vv12[i] = (vv3 >> (6 * (3 - i))) & 0x3F  
       else:  
           vv12[i] = 64  
       gg.append(vv12[i])

ppp = [39, 17, 24, 4, 25, 35, 3, 46, 42, 49, 45, 37, 11, 60, 11, 58, 4, 26,
45, 2]

for i in range(20):  
   s.add(gg[i] == ppp[i])

print(s.check())

m = s.model()

flag = {}

for d in m.decls():  
   flag[int(d.name()[1:])] = m[d].as_long()

w = ''

for i in sorted(flag):  
   w += chr(flag[i])

print(w)

```  
# Key: SE8D0-vsctf-2K31P-4begi-AD648-nnerz

# FLAG

**`vsctf{you_are_good_at_z3,but_maybe_i_should_play_genshin_impact_first?}`**

Original writeup
(https://github.com/acdwas/ctf/tree/master/2022/vsCTF%202022/rev/Tuning%20Test).