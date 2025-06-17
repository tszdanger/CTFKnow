### rev/universal

This challenge presents an obfuscate quantum circuit for performing addition
based on the [Quantum Fourier Transform adder](https://github.com/the-entire-
country-of-ireland/public-quantum-
rev/blob/main/Quantum%20Rev%202/solve/writeup.md), which is the same addition
algorithm featured in the linked writeups from last year's quantum rev
challenges. The goal is to determine that number is being added.

The obfuscation comes from that all of the `Rz(theta)` rotations have been
converted into long sequences of `H` and `T` gates -- thus making the entire
quantum circuit only use `H, T, CNOT` gates. The program I used for this was
[gridsynth](https://www.mathstat.dal.ca/~selinger/newsynth/), which is much
more efficient than other approaches, eg as given by the construction of the
Solovay-Kitaev theorem. No other obfuscations were applied, apart from those
required to convert controlled-rotations into a mix of CNOT and single-qubit
gates.

```  
    $ gridsynth pi/128  
    SHTHTHTHTHTHTHTSHTHTHTHTSHTHTHTHTHTSHTSHTHTHTHTHTSHTHTHTSHTSHTHTSHTSHTSHTHTHTHTS  
    HTHTHTHTHTSHTSHTHTSHTHTSHTSHTSHTSHTHTSHTSHTSHTSHTHTHTSHTSHTSHTHTHTHTSHTHTSHTHTHT  
    SHTHTHTHTSHTHTSHTHTSHTSHTSHTHTHTHTHTHTHTSHTHTSHTHTHTSHTSHTHTHTSHTSHTSHTHTSHTHTHT  
    HTSHTSHTSHSSSWWWWWWW  
```

The intended solution analyzes the structure of the QFT to isolate where the
actual rotations are beign applied. The QFT consists of a long chain of CNOT
gates and Rz rotations. The actual adder component consists of only Rz
rotations, with no CNOT gates. So the longest chain of gates in the circuit
which contains no CNOT gates is the adder. This is the only component which
you need to statically analyze. You can determine this by reading about how
the QFT works, or by looking at the generate.py script from last year's
challenges.

The following solution is essentially a quantum disassembler. For each single-
qubit chain of H and T gates, it multiplies the gates together to determine
what the quantum operator is. Then it determines that the corresponding
Z-rotation angle is for this operator.

Once all the rotation angles have been recovered, extracting the number being
added (ie the flag) [proceeds identically to quantum-rev 2 from last
year](https://github.com/the-entire-country-of-ireland/public-quantum-
rev/blob/main/Quantum%20Rev%202/solve/writeup.md).

```python  
from math import pi, log2  
import numpy as np

# hadamard gate  
H = 1/np.sqrt(2)*np.array([[1, 1],  
                          [1,-1]], dtype=np.complex128)  
# T-phase gate  
T = np.array([[1, 0],  
             [0, np.exp(1j * pi/4)]], dtype=np.complex128)  
# identity operator  
I = np.array([[1, 0],  
             [0, 1]], dtype=np.complex128)

########################################

# num qubits  
n = 256  
# max error  
epsilon = 1e-4

"""  
look for the start/end of the QFT.  
This includes a few extra gates (from the QFT)  
for qubit 0 and 1, so we just ignore those  
"""

idcs = []  
with open("converted_circuit.qasm", "r")  as f:  
   for i,line in enumerate(f):  
       if line == "cx q[1],q[0];\n":  
           idcs.append(i)  
           # print(i)

i0 = idcs[1]  
i1 = idcs[2]

lines = open("converted_circuit.qasm", "r").readlines()  
idcs = [i for i,line in enumerate(lines)]  
gates = lines[i0 + 1:i1 - 1]

########################################

unitaries = [I for _ in range(n)]

for line in gates:  
   instr = line[0]  
   qubit = line[line.find("[")+1:line.find("]")]  
   qubit = int(qubit)  
  
   i = qubit  
   if instr == 't':  
       unitaries[i] = unitaries[i] @ T  
   elif instr == 'h':  
       unitaries[i] = unitaries[i] @ H  
   else:  
       raise ValueError("invalid gate")  

# correct for QFT spillover  
for i in range(3):  
   unitaries[i] = I

########################################

binary_reprs = ""  
unitaries = unitaries

for i,u in enumerate(unitaries):  
   delta = np.abs(u) - I  
   if np.max(np.abs(delta)) > epsilon:  
       raise ValueError("unitary is not approximately a phase gate")  
  
   u /= u[0][0]  
   angle = np.angle(u[1][1])  
  
   b = str(int(angle < 0))  
   binary_reprs += b

flag = int(binary_reprs[::-1], 2).to_bytes(n//8, "little")  
# first character is wrong b/c we included some extra QFT gates lol  
flag = b"d" + flag[1:]  
print(flag)  
```

However, during the competition the only solves were from a very amusing
approach -- just run the program and it prints out the flag! Apparently the
circuit simulator used in qiskit is able to very efficiently emulate the
circuit in this problem without ever constructing the full statevector. The
statevector has length `2^256`, so I had assumed that classically simulating
the output would be completely impossible. Clearly, the IBM engineers and
scientists behind qiskit deserve a raise >_<.

The runtime of the below script for me is 45 minutes and it takes < 4 gigs of
ram -- much less than 2^256!

```python  
from qiskit import QuantumCircuit, Aer, execute  
simulator = Aer.get_backend('aer_simulator')  
qc = QuantumCircuit.from_qasm_file("converted_circuit.qasm")

# add some measurement gates at the end  
qubits = list(range(256))  
qc.measure(qubits, qubits)  
job = execute(qc, simulator)  
result = job.result()  
print(result.get_counts())

num_chars = 256 // 8  
x = list(result.get_counts().keys())[0]  
f = int(x, 2).to_bytes(num_chars, "little")  
print(f)  
```

Original writeup (https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ?view#revuniversal).### **Title:** rev/universal

**Hint:** A smart bruteforcer to figure-out flag chars

**Solution:**\  
I used online tools for decompiling the java class file and saved it in the
FlagChecker.java

From the code we can deduce that, flag is 38 chars length and  
each char byte is used in some binary operations.

Also, we can assume that the flag starts with 'lactf{' and ends with '}' and  
contains alphanum with underscore as characters.

As, we know 0-5 and 37 indices of the flag. We can go ahead and find the
conditionals  
where we can plug and deduce other chars.

So, by using these new obtained chars we can determine other chars in the same
way.

Please find the full code for the solution in [here](reverse.py).

**Exploit:** ./reverse.py

**Flag:** `lactf{1_d0nt_see_3_b1ll10n_s0lv3s_y3t}`  

Original writeup
(https://github.com/kalyancheerla/writeups/tree/main/2023/lactf/universal).