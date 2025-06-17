# quantum-2

## Challenge Description  
Let's increase the difficulty. Same algorithm, new circuit.

In practice, quantum compilers and programmers make use of techniques which
don't exist in classical reversible computing, even for seemingly classical
subroutines. While this circuit has more gates than the `quantum 1` circuit,
it also requires much fewer qubits. In fact, the main computational step only
uses [2n+3 qubits](https://arxiv.org/abs/quant-ph/0205095).

provided files  
- ./circuit_parts.7z  
- ./encrypted_message.rsa

## Challenge Overview

`quantum-2` is a harder version of the same challenge. While `quantum-1` used
a purely classical reversible circuit to compute the modular exponentiation
step of Shor's algorithm, `quantum-2` uses a quantum subroutine. Specifically,
`quantum-1` used the [Cuccaro ripple-carry adder](https://arxiv.org/abs/quant-
ph/0410184) to add two numbers stored in quantum memory.

However, in Shor's algorithm, you only ever need to add classical numbers to
numbers to stored in quantum memory. You can save a lot of ancillary qubits by
using a different quantum addition subroutine -- namely, addition based on the
Quantum Fourier Transform (QFT).

Some relevant papers are:  
- https://arxiv.org/abs/1411.5949  
- https://arxiv.org/abs/quant-ph/9511018  
- https://arxiv.org/abs/quant-ph/0008033

The QFT is used at the end of the circuit, so players should recognize the
repitition, but I also explicitly linked the paper in the challenge
desciption. It's also the top result if you google "quantum addition
algorithm".

The QFT-adder performs addition by taking the QFT of the input qubits, and
then performing controlled rotations. The controlled rotations are controlled
against a classical register, not a quantum register, so there will either be
a rotation or not. ie, the "controlled" part of it is optimized away during
compilation. You can use this to figure out what the classical register bits
are: if there is a rotation, then the control bit is 1. Compare against "the
paper" to identify what the control bits should be to produce those rotations
-- this is the classical number which is being added. There's a slight
complication that we coalesce all the rotations of the same qubit together, so
you have to do a bit of math.

Once you understand how the QFT-adder works and how to extract the classical
numbers from the circuit, recovering `N` is actually easier than in
`quantum-1`. This is because `N` is hardcoded the 2nd time the QFT-adder is
called -- no baby number theory required! But the core approach is still
seeing which numbers are being added and looking for a pattern. Obtaining the
flag once you've found `N` is identical to in `quantum-1`.

## QFT analysis

Here's an example of how to analyze the quantum circuit to extract the number
being added from the rotation angles.

Most of the phase / z-rotation gates in the circuit files are just
implementing the QFT. However, all of the phase gates which actually encode
the numbers being added are multiply-controlled phase gates. This is the only
context in which `mcphase` gates appear in the circuit, so you can simply grep
the circuit files to extract the rotation angles. Guessing this is not
necessary, as you can simply analyze all consecutive sequences of phase gates
whose length is near 64.

`grep mcphase ../challenge/circuit_parts/circuit_z_0.qasm -A 0 >
output_z_0.txt`

The last few angles from the first such rotation are:  
```  
mcphase(0.96947586) q[128],q[0],q[201];  
mcphase(1.9389517) q[128],q[0],q[200];  
mcphase(3.8779034) q[128],q[0],q[199];  
mcphase(1.4726216) q[128],q[0],q[198];  
mcphase(15*pi/16) q[128],q[0],q[197];  
mcphase(15*pi/8) q[128],q[0],q[196];  
mcphase(7*pi/4) q[128],q[0],q[195];  
mcphase(3*pi/2) q[128],q[0],q[194];  
mcphase(pi) q[128],q[0],q[193];  
```

The appearance of `pi` on the final angles indicates that you should convert
divide each floating point number by (2 * pi), which will then give a fraction
where the denominator is a power-of-2. This is also explained in the paper.

```  
0.1542968753272663  
0.30859374747143375  
0.6171874949428675  
0.23437500694389587  
0.46874999999999994  
0.9374999999999999  
0.875  
0.75  
0.5  
```

Trying out a few possible values for the denominator reveals that all of the
new floating point numbers can be written as a fraction where the denominator
is `2^12`. The corresponding numerators are `[0, 2048, 3072, 3584, 3840, 1920,
960, 2528, 1264]`, whose binary representation is:

```  
[+] 8   1264    010011110000  
[+] 7   2528    100111100000  
[+] 6   960     001111000000  
[+] 5   1920    011110000000  
[+] 4   3840    111100000000  
[+] 3   3584    111000000000  
[+] 2   3072    110000000000  
[+] 1   2048    100000000000  
[+] 0   0       000000000000  
```

The diagonal pattern is pretty clear. You can read off the binary
representation of the number being added by looking at the most significant
bit of the denominator, in this case (from bottom-to-top) `[0, 1, 1, 1, 1, 0,
0, 1, 0, ...]`. Read the paper to understand why.

## Extracting `N`

The [attached] solve script analyzes the first 20 additions present in the
`circuit_z_0.qasm` file, and obtains:  
```  
1149389920988353694  
1149785239057719001  
395318069365307  
395318069365307  
1148994602918988387  
1149785239057719001  
790636138730614  
790636138730614  
1148203966780257773  
1149785239057719001  
1581272277461228  
1581272277461228  
1146622694502796545  
1149785239057719001  
3162544554922456  
3162544554922456  
1143460149947874089  
1149785239057719001  
6325089109844912  
6325089109844912  
...  
```

The pattern here is `N-a, N, a, a, N-2*a, N, 2*a, 2*a, N-4*a, ...`, which is
pretty similar to what appeared in `quantum-1`.  

Original writeup (https://github.com/the-entire-country-of-ireland/public-
quantum-rev/blob/main/Quantum%20Rev%202/solve/writeup.md).