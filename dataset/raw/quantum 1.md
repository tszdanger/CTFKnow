# quantum-1

## Challenge Description  
We've found some sort of advanced codebreaker machine, and some encrypted
messages it was trying to break. Can you crack it first?

Hint: This circuit is implementing a famous quantum algorithm to factor the
public modulus. This modulus *should* be stored in the classical memory before
evaluating the circuit (and immediately copied via `cnot` to the quantum
memory during `circuit_initialization.qasm`), but is not provided in the
challenge. However, the modulus was used to derive many numbers which are used
by subroutines in the quantum algorithm, and all of those numbers are
hardcoded in the circuit.

Hint: modular exponentiation is just repeated conditional modular
multiplication, and modular multiplication is just repeated conditional
modular addition, and modular addition is just several regular additions.

provided files  
- ./circuit_parts.7z  
- ./encrypted_message.rsa

## Challenge Overview  
We're provided with a quantum circuit implementing Shor's algorithm to factor
a number N, as well as a collection of ciphertexts encrypted with N. The goal
of this challenge is to analyze the quantum circuit and extract the modulus N,
which is sufficiently small (< 64 bits) that it can be factored classically.
Then you can use this to decrypt the ciphertexts.

Shor's algorithm consists of 4 stages on the quantum computer:  
1) hadamards / prepare a uniform superposition  
2) modular exponentiation  
3) quantum fourier transform  
4) measurement

There's classical post-processing on extracting the period and using that to
factor N, but we'll ignore that and focus on the quantum component.

The key point is that most of Shor's algorithm is just computing a modular
exponentiation step `a^x mod N`, which is implemented via repeated squaring.
So the exponentiation step is broken down into repeated controlled modular
multiplication. Modular multiplication is then implemented via repeated
additions and negations. In this challenge, addition is performed via the
[Cuccaro ripple-carry adder](https://arxiv.org/abs/quant-ph/0410184). A very
brief overview is presented in [section II.B of this
paper](https://arxiv.org/abs/1905.09749). But understanding how it works in-
detail isn't too necessary, as long as you get that its implementing addition.

While `N` itself is never explicitly loaded (the quantum circuit expects it to
be provided as input, which is then copied over to quantum memory), many
values which depend on `N` are hardcoded into the circuit.  Specifically,
`pow(a, pow(2,i)) * pow(2,j) % N for j in range(64) for i in range(128)`.

Players should first get a [high-level familiarity with Shor's
algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm), and then
identify which qubits are being used as the exponent qubits via the Hadamard
gates at the beginning of the circuit.

## static analysis solution

When analyzing the circuit, players should notice that while the circuit
itself is large, it is massively repetitive, hence why it compresses down to
under a MB. Thus, they should look at trying to identify repeated chunks of
code as functions. This will lead them to the addition function. All of stage
2) can be efficiently simulatable, so players can emulate the function with
concrete inputs and see that it performs addition in little-endian. However,
this is not necessary.

Next, players should look at the arguments being passed to the function. A lot
of the arguments are directly loadly immediately beforehand, via the `ccx`
instruction where the first argument is an exponent qubit, example:

```  
ccx q[0],q[128],q[384];  
ccx q[0],q[128],q[386];  
...  
ADDITION_CIRCUIT;  
```

In classical reversible computing, `ccx` is often used as a conditional-
conditional-write. The above is flipping registers `q[384]` and `q[386]` if
and only if registers `q[0]` and `q[128]` are `1`. Because `384 = 6 * 64`,
this indicates that these destination registers are part of a single 64-bit
variable, and the circuit snippet is really performing a conditional write of
`1010000000000...` to that variable. With little-endian encoding, this is
writing `5`.

Continue analyzing the circuit and see what other values are being written to
this variable, conditioned on an exponent qubit, right before the addition
function is called. Players should notice that the numbers loaded are being
computed `mod N`, and then do some basic number theory to recover `N`.

A possible approach is in the provided `solve_static.py` python script, with
the output for the 1st circuit_part file saved in `rewritten_circuit.txt`. A
short selection of the rewritten code is below:  
```  
ccx q[0],q[128], `74583193119493` -> #6  
add #5, #6  
negate #5  
add #5, #3  
negate #5  
ccx q[449], #3, #4  
add #4, #5  
negate #5  
add #6, #5  
negate #5  
add #5, #6  
x q[449];  
ccx q[0],q[128], `74583193119493` -> #6  
ccx q[0],q[129], `149166386238986` -> #6  
add #5, #6  
negate #5  
add #5, #3  
negate #5  
ccx q[449], #3, #4  
add #4, #5  
negate #5  
add #6, #5  
negate #5  
add #5, #6  
x q[449];  
ccx q[0],q[129], `149166386238986` -> #6  
ccx q[0],q[130], `298332772477972` -> #6  
...  
```  
Examining the disassembled code reveals that it is loading repeated doublings
of `a = 74583193119493` into register #6, but after a certain point the
numbers plateau off and stop monotonically increasing. This is because the
doublings are happening mod N, which lets you recover N from a single
circuit_part file.

Once `N` has been recovered, you can factor it in sage in under a minute.
Using the public exponent `e = 65537 (0x10001)`, you can then compute `d` and
decrypt the ciphertext to get the flag.

##  dynamic analysis solution

The circuit_part files only use SWAP, NOT, CNOT, and CCNOT gates, which are
all classical gates, so you can emulate the circuit. At the very start of each
file, it loads in `a, a^2, a^4, a^8, ...`, so pausing the emulation after the
first values have been loaded will reveal the modular powers of `a`.

We know that `a^2 - (a^2 mod N)` is a multiple of `N`, so you can recover (a
small multiple of) `N` via:  
```  
gcd( a^2 - (a^2 mod N), a^4 - (a^4 mod N) )  
```

Unfortunately, as `N` is not loaded during the circuit (it is expected to be
provided in classical memory and then copied over to quantum memory during the
initialization routine), the entire circuit cannot be correctly emulated.

## hindsight 2021

When designing the challenge, I had made the decision to not hardcode `N` into
the circuit, as I thought that this would make it too easy to solve. Instead,
I wanted teams to recover the modular powers and doublings of `a` and use that
to recover `N`.

This turned out to be a bad call and made the challenge frustrating, as few
teams were able to recover any of the integers hardcoded into the circuit.
Additionally, not having `N` loaded meant that teams could not successfully
emulate the entire modular exponentiation subroutine, which would have been a
very elegant solution.

As few teams were able to solve the first quantum challenge, and the entire
series could only be solved sequentially, we chose to not release the third
and final quantum challenge `='(`.  

Original writeup (https://github.com/the-entire-country-of-ireland/public-
quantum-rev/blob/main/Quantum%20Rev%201/solve/writeup.md).