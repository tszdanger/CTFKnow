# Sakura - Reversing - 218 points - 50 teams solved

> She accompanies me every night.  
>  
> [sakura-fdb3c896d8a3029f40a38150b2e30a79](./sakura-
> fdb3c896d8a3029f40a38150b2e30a79)

This binary reads 400 bytes from stdin, runs a lot of verification tests on
the input, then gives the flag as the SHA256 hash of the input. While the
verification function is huge (and makes Hex-Rays choke a bit), it is pretty
neatly structured. Each step adds up different digits from the input then
verifies that the sum of those digits match.

Our [angr](http://angr.io/) skills are a bit rusty, and this seems like an
ideal task to freshen up those skills. The thing that worked really well this
time was the `avoid` parameter to `explore()` - the verification function
doesn't return instantly on failure, it just clears a flag then continues
executing the rest of the function - if we just told `angr` to reach the flag
printing code, it would spend a lot of time analyzing dead paths. So we give
it a list of addresses that instantly terminate an analysis branch if ever
reached, cutting significantly down on the amount of work the analyzer has to
do. We also hacked in some step-by-step debugging output by doing `explore()`
in smaller chunks to see how well `angr` is doing, though there's probably
some better way to do this.

After a few minutes, `angr` had found valid input, and we fed it into the
program and got the flag in return -
`hitcon{6c0d62189adfd27a12289890d5b89c0dc8098bc976ecc3f6d61ec0429cccae61}`  

Original writeup (https://github.com/ymgve/ctf-
writeups/tree/master/hitcon2017quals/rev-sakura).# LINE CTF 2021 - Reversing - Sakura

## TL;DR  
- Some Solidity smart contracts and the CLI application (webpacked) to manipulate them are given.  
- The flag is output when the state of multiple accounts is badly transitioned.  
  - The state referred to here is not the `State` defined in the contract.  
- Since there are only a few possible choices in the CLI application, **fuzzing** can solve this problem.

## Problem  
>Sakura is beautiful  
>nc 34.84.178.140 13000

The given files:  
```  
.  
├── contracts  
│   ├── Contract.sol  
│   └── openzeppelin  
│       └── contracts  
│           ├── access  
│           │   └── Ownable.sol  
│           └── utils  
│               └── Context.sol  
├── (flag)  
└── index.js  
```

## Solution  
`Contract.sol` is the core code of the app, `index.js` is the CLI application
that manipulates the contract (the bytecode of the contract is embedded).
`openzeppelin` is the standard library for contracts; thus, we do not need to
read it.

We access the app with `nc` (or run it locally) and then get the following
results and select a choice.  
```txt  
❯ nc 34.84.178.140 13000  
Loading...  
Account: 0x66ab6d9362d4f35596279692f0251db635165871  
Account: 0x33a4622b82d4c04a53e170c638b944ce27cffce3  
Account: 0x0063046686e46dc6f15918b61ae2b121458534a5  
Set player account a balance of 100 ETH  
Compiling...  
Deploying the contract...  
Contract address: 0xe7cb1c67752cbb975a56815af242ce2ce63d3113  
--------------------------------------  
Welcome to Timeless Sakura Prediction Game

- You can get ETHs if you predict the future.  
- Oracle system that go beyond powerful time will judge.  
- We have GOD level BFT consensus model, Ethereum based single node blockchain.  
 (Yeah, We've solved the bloody byzantine general problem)  
- We use a smart contract engine based on a powerful EVM, the World computer.

--------------------------------------  
Today's question is

   What will be the weather tomorrow?

   1) Sunny  
   2) Rainy

--------------------------------------  
1) Bet  
2) Cancel  
3) Get Player's Balance  
4) Finalize  
```

First, we operate the app and then find the following.  
- The `Oracle response` we get in the `Finalize` choice is the opposite of the input of the `Bet` choice. It seems good if these are the same value.  
- The `Bet` choice reduces the balance of the accounts. If we cancel, it returns.  
- We can only enter a choice up to five times.  
- If proper input and proper order are not followed, transactions revert.  
  - Example: `Tx Reverted: [ 'Invalid state' ] { error: 'revert', errorType: 'VmError' }`  
- The number and content of transactions revert changes depending on the order of selection. There are probably transactions for multiple accounts.  
- etc.

Next, if we look for how `flag` is output, we find it in `index.js`.  
- `case 1: return 1 == I.sent().balance.gt(new Y.BN(G.convert("1000", "eth", "wei"))) && (console.log("win!"), console.log(k.readFileSync("/flag", "utf8"))), [2]`  
- We can see that the flag will probably be output when the balance of my account exceeds 1000 ETH.  
- If we change this 1000 value, the flag is actually be displayed at the timing of the `Finalize` choice.

We assume that there is a sequence of choices whose length is less than five
that will output a flag. We can use a fuzzing approach.  
The code is as follows.  
```py  
import subprocess  
import itertools  
from concurrent.futures import ProcessPoolExecutor

cands = [(1, 0), (1, 1), (1, 3), (2,), (3,)]

zenbu = [c + ((4,),) for c in itertools.product(cands, repeat=4)]

def work(tup):  
   print(tup)  
   proc = subprocess.Popen(["node", "sakura/index.js"],  
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE)

   s = "\n".join(str(x) for x in itertools.chain(*tup))+"\n"

   stdout, stderr = proc.communicate(s.encode())  
   stdout = stdout.decode()

   if "win!" in stdout or "LINECTF" in stdout:  
       print("!" * 1000, tup)  
       open("!!!.txt", "w").write(str(tup))  
       exit(0)

with ProcessPoolExecutor(max_workers=4) as executor:  
   executor.map(work, zenbu)  
```

We enter `(1,1),(1,3),(4,)` and then get the flag.

`LINECTF{S4kura_hira_hira_come_to_spring}`  

Original writeup
(https://github.com/x-vespiary/writeup/blob/master/2021/03-line/rev-
sakura.md).