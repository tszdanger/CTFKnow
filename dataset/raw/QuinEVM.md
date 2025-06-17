# QuinEVM Writeup

### LakeCTF 2022 - blockchain 388 - 16 solves

> Do you even quine bro? `nc chall.polygl0ts.ch 4800` [quinevm.py](quinevm.py)

#### Analysis

Python script is given. Below code is the relevant logic to get flag. I must
make `verify` method to return `True`.

```python  
def verify(addr):  
   code = web3.eth.get_code(addr)  
   if not 0 < len(code) < 8:  
       return False

   contract = web3.eth.contract(addr, abi=[ { "inputs": [], "name": "quinevm",
"outputs": [ { "internalType": "raw", "name": "", "type": "raw" } ],
"stateMutability": "view", "type": "function" } ])  
   return contract.caller.quinevm() == code

if __name__ == "__main__":  
   addr = input("addr? ").strip()  
   if verify(addr):  
       gib_flag()  
   else:  
       print("https://i.imgflip.com/34mvav.jpg")  
```

Upper python snippet first asks me to provide valid ethereum address, which
satisfies below two conditions. If those conditions are met, I get flag.

1. Contract bytecode length must be less than `8`.  
2. Contract bytecode must be equal to the return value of method `quinevm` implemented in the contract.

In other words, I must implement a
[quine](https://en.wikipedia.org/wiki/Quine_(computing)), a program which
takes no input and produces a copy of its own source code as its only output.
I now know why the challenge name is QuinEVM.

#### EVM Assembly Fun

To implement EVM quine which code size is less than `8`, I must code my
contract by using [EVM assembly](https://ethervm.io/). Let me try to abuse
[`CODESIZE`](https://ethervm.io/#38), [`CALLVALUE`](https://ethervm.io/#34),
and [`CODECOPY`](https://ethervm.io/#39).

I first set the `value` of [ethereum
transaction](https://ethereum.org/en/developers/docs/transactions/) to be `0`
wei, to make [`CALLVALUE`](https://ethervm.io/#34) to push `0` to EVM stack.

1. `38`:`CODESIZE` : Push `7`: length of the executing contract's code in bytes  
2. `34`:`CALLVALUE`: Push `0`: message funds in wei  
3. `34`:`CALLVALUE`: Push `0`: message funds in wei  
4. `39`:`CODECOPY` : Pop `0, 0, 7`: `memory[0:7] = address(this).code[0:7]`  
   - `memory[0:7]` will store entire contract bytecode itself.  
5. `38`:`CODESIZE` : Push `7`: length of the executing contract's code in bytes  
6. `34`:`CALLVALUE`: Push `0`: message funds in wei  
7. `F3`:`RETURN`   : Pop `0, 7`: `return memory[0:7]`  
   - return value will be the entire contract bytecode itself.

Upper bytecode satisfies quine property. It is because when
`contract.caller.quinevm()` is called, EVM will start to execute upper seven
bytecode step by step. Eventually it will return its own bytecode.

The final payload is: `383434393834F3` which having length `7`, satisfying
length contraints and being EVM quine.

#### Truffle to get flag

There are bunch of toolkits to interact with rpc node. Hardhat, Foundry, curl,
etc. This time, I will use [Truffle](https://trufflesuite.com/) to deploy and
test my solution.

Let me boot up truffle.

```sh  
$ truffle develop  
```

This spawns truffle node and generates accounts which are funded. I also get
interactive truffle shell: `truffle(develop)>`.

```  
Truffle Develop started at http://127.0.0.1:9545/

Accounts:  
(0) 0xe3d79d970545aad6656cf97c9b65ed657ff6acf4  
...  
truffle(develop)>  
```

Let me test my exploit and get deployed contract address.
[Attack.sol](contracts/Attack.sol) is implemented to deploy contracts using
[`CREATE`](https://ethervm.io/#F0).

```solidity  
contract Attack {  
   event Result(address addr, bytes bytecode);

   function deployBytecode(bytes memory bytecode) public returns (address) {  
       address addr;  
       uint256 length = bytecode.length;  
       /*  
           NOTE: How to call create

           create(v, p, n)  
           create new contract with code at memory p to p + n  
           and send v wei  
           and return the new address  
       */  
       assembly {  
           addr := create(  
               0,                   // 0 wei sent  
               add(bytecode, 0x20), // ignore offset data. Can be hardcode to 0xa0   
               length               // bytecode length  
           )  
       }  
       emit Result(addr, addr.code);  
       return addr;  
  }  
}  
```

[TestAttack.sol](test/TestAttack.sol) tests using
[Attack.sol](contracts/Attack.sol) and check quine property.

```solidity  
import "../contracts/Attack.sol";

contract TestAttack {  
   function testAttack() public {  
       Attack attack = Attack(DeployedAddresses.Attack());

       bytes memory bytecode = hex"383434393834F3";  
       require(bytecode.length < 8, "BYTECODE_LENGTH_TOO_LONG");  
       /*  
           len(bytecode) == 7

           38: CODESIZE     // 7  
           34: CALLVALUE    // 0   
           34: CALLVALUE    // 0  
           39: CODECOPY     // memory[0:7] = address(this).code[0:7]  
           38: CODESIZE     // 7  
           34: CALLVALUE    // 0  
           F3: RETURN       // return memory[0:7]  
       */  
  
       address addr = attack.deployBytecode(bytecode);  
       bytes memory bytecode_deployed = addr.code;

       Assert.equal(keccak256(bytecode), keccak256(bytecode_deployed), "bytecode mismatch");  
   }  
}  
```

Provide `--show-events` to get address value. `Result` event is implemented to
get deployed address.

```  
truffle(develop)> truffle test --show-events  
Using network 'develop'.

Compiling your contracts...  
===========================  
> Compiling ./contracts/Attack.sol  
> Compiling ./test/TestAttack.sol  
> Artifacts written to /var/folders/59/r65q4pf91ljc5b472641b4940000gn/T/test--
> 14304-haT2sXVvcGJn  
> Compiled successfully using:  
  - solc: 0.8.13+commit.abaa5c0e.Emscripten.clang

 TestAttack  
   ✔ testAttack (51ms)

   Events emitted during test:  
   ---------------------------

   Attack.Result(  
     addr: 0x71Ce7C82A7ABA3dAdF59bf0beb2530116C496d52 (type: address),  
     bytecode: hex'383434393834f3' (type: bytes)  
   )

   ---------------------------

 1 passing (2s)  
```

Everything looks great. Lets provide address
`0x71Ce7C82A7ABA3dAdF59bf0beb2530116C496d52` to our challenge python snippet.
RPC tweaked to truffle node.

```  
$ python quinevm_local.py  
addr? 0x71Ce7C82A7ABA3dAdF59bf0beb2530116C496d52  
```

My juicy flag:

```  
EPFL{https://github.com/mame/quine-relay/issues/11}  
```

Full exploit code: [Attack.sol](contracts/Attack.sol) requiring [truffle-
config.js](truffle-config.js)

Exploit test: [TestAttack.sol](test/TestAttack.sol)

Python snippet dependency: [requirements.txt](requirements.txt)

Problem src: [quinevm.py](quinevm.py)

Modified problem src: [quinevm_local.py](quinevm_local.py): RPC tweaked to
truffle node.  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2022/Lake/QuinEVM).