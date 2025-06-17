# Karen Writeup

### zer0pts CTF 2022 - crypto 304 - 8 solves

>
> [karen_09b3e12d31dec5649953b2a2613c05c3.tar.gz](karen_09b3e12d31dec5649953b2a2613c05c3.tar.gz)

#### Analysis

Problem source:

```python  
with open("flag.txt", "rb") as f:  
   flag = int.from_bytes(f.read(), "big")

n = 70  
m = flag.bit_length()  
assert n < m  
p = random_prime(2**512)

F = GF(p)  
x = random_matrix(F, 1, n)  
A = random_matrix(ZZ, n, m, x=0, y=2)  
A[randint(0, n-1)] = vector(ZZ, Integer(flag).bits())  
h = x*A

print(p)  
print(list(h[0]))  
```

`n = 70`, `p` is 512 bit prime.  
`x` is 1 by `n` matrix which its elements are chosen randomly in `Zmod(p)`.  
`A` is `n` by `m` matrix which elements are chosen randomly in `Zmod(2)`. `m =
351` which is flag's bit length.  
Single row's `A` will be substituted to `Integer(flag).bits()`. We only know
`p` and `h = x * A`(`1` by `m` matrix).  
Our goal is to recover every element of `A` and recover flag.

### Guess the paper!

The problem reminds me of knapsack cipher, or 0/1 knapsack problem. The hard
part is that, we only know the encrypted message, not public key. This problem
is called the **Hidden Subset Sum Problem**. The paper: [A Polynomial-Time
Algorithm for Solving the Hidden Subset
Sum](https://eprint.iacr.org/2020/461.pdf) which was accepted to CRYPTO20
shows the state-of-art algorithm to solve this specfic problem. The paper even
provides juicy sagemath code :D.

So, does the given contraint: `n = 70` and `m = 351` are feasible to be
solved? Yes, the paper also provides the implementation of Nguyen-Stern
algorithm, which is less powerful than the author's new algorithm. By doing
some experiments, I successfuly applied the Nguyen-Stern algorithm to the
given output and got the flag:

```  
zer0pts{Karen_likes_orthogonal_as_you_like}  
```

Problem src and output: [task.sage](task.sage), [output.txt](output.txt)

exploit driver code: [solve.sage](solve.sage) with [output.py](output.py)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2022/zer0pts/Karen).