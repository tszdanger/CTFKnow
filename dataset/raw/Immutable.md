# Immutable Writeup

### LakeCTF 2022 - blockchain 372 - 17 solves

> Code is law, and whatever's on the blockchain can never be changed. `nc
> chall.polygl0ts.ch 4700` [immutable.py](immutable.py)

#### Analysis

Python script is given. The script has three menus: `audit()`, `rugpull()` and
`exit()`. To gain flag, I must execute below control flow.

1. `audit()`:  
   - Supply contract address `addr`.   
   - Check given address is a contract, not [EOA](https://ethereum.org/en/whitepaper/#ethereum-accounts) by checking code size.  
   - Check `target(addr)` is **NOT IN** contract's bytecode. `target(addr)` is known to everyone, and is the hash of `addr` with padding.  
   - After all check is passed, it will return a `proof = auth(addr)`. `proof` can only be generated by the script because it depends on secret value `KEY`.  
2. `rugpull()`:  
   - Supply contract address `addr`.  
   - Supply `proof` which was obtained using `audit()`  
   - Check `target(addr)` is **IN** contract's bytecode. If it is in, give flag. To get `proof`, I must pass `audit()`, and it already checkd `target(addr)` is **NOT IN** contract's bytecode.

Therefore the objective of the challenge is to update a code of a deployed
contract. This update logic must be done between `audit()` and `rugpull()`.

### Contract Creation/Destruction Internals

Let me gather information of contract creation and destruction.

1. [`CREATE`](https://ethervm.io/#F0) : `create(v, p, n)` creates a new contract with code at memory `p` to `p + n` and send `v` wei and return new address computed by `keccak256(msg.sender ++ nonce)[12:]`. [Ref](https://github.com/ethereum/go-ethereum/blob/2b44ef5f93cc7479a77890917a29684b56e9167a/crypto/crypto.go#L107). Nonce is incremented when contract creation.  
2. [`CREATE2`](https://ethervm.io/#F5) : `create2(v, p, n, s)` creates a new contract with code at memory `p` to `p + n` and send `v` wei and return new address commputed by `keccak256(0xff ++ msg.sender ++ salt ++ keccak256(init_code))[12:]`. [Ref](https://github.com/ethereum/go-ethereum/blob/2b44ef5f93cc7479a77890917a29684b56e9167a/core/vm/evm.go#L503).  Nonce is incremented when contract creation. To redeploy to same address using `create2`, the contract must be self destructed or never been deployed.  
3. [`SELFDESTRUCT`](https://ethervm.io/#FF): `selfdestruct(address(addr))` destroys the contract and sends all funds to addr. It also resets the nonce.

### Exploit Scenario

1. Deploy [Factory](contracts/Factory.sol) contract.   
2. Deploy [Solution](contracts/Solution.sol) contract using `CREATE2`, using `salt` as `pcw109550` at [Factory](contracts/Factory.sol) contract.  
3. Deploy [Contract1](contracts/Contract1.sol) contract using `CREATE`, at [Solution](contracts/Solution.sol) contract.  
   - [Contract1](contracts/Contract1.sol) contract address will be the address which bytecode becomes mutable.  
4. Call `audit()`  
   - Give [challenge script](immutable.py), [Contract1](contracts/Contract1.sol) contract address `addr` and get `proof` of it. `target(addr)` is not in [Contract1](contracts/Contract1.sol) contract's bytecode so possible.  
5. `SELFDESTRUCT` [Contract1](contracts/Contract1.sol) contract and [Solution](contracts/Solution.sol) contract.  
   - [Solution](contracts/Solution.sol) contract nonce is reset.  
6. Redeploy [Solution](contracts/Solution.sol) contract using `CREATE2`, using `salt` as `pcw109550` at [Factory](contracts/Factory.sol) contract. Contract address is not changed because I used the same `salt`.  
7. Deploy [Contract2](contracts/Contract2.sol) contract using `CREATE`, at [Solution](contracts/Solution.sol) contract.  
   - [Contract2](contracts/Contract2.sol) contract address will be equal to `addr` because [Solution](contracts/Solution.sol) contract was self destructed, and its nonce was reset. Nonce and parent contract address not changed so possible.  
   - Make `target(addr)` be the bytecode of [Contract2](contracts/Contract2.sol) contract. This is because to get flag while executing `rugpull()` in challenge script.  
7. Call `rugpull()`  
   - Give [challenge script](immutable.py), [Contract2](contracts/Contract2.sol) contract address `addr` and `proof` obtained at step 4.  
   - At this point, `target(addr)` is included in the bytecode of contract `addr`, so I get flag.

### Implementation

I first tested the upper scenario using truffle test,
[TestSolution.sol](test/TestSolution.sol) using dummy `target(addr)` value.
After that, I wrapped everything in [solution.js](test/solution.js) ans
wrapped it again using [pwntools](https://github.com/Gallopsled/pwntools),
implemented at [solve.py](solve.py). It first boots up truffle node, and runs
exploit script.

I get flag:

```  
EPFL{https://youtu.be/ZgWkdQDBqiQ}  
```

Full exploit code: [solve.py](solve.py) requiring [truffle-config.js](truffle-
config.js)

Exploit test: [TestSolution.sol](test/TestSolution.sol)

Python snippet dependency: [requirements.txt](requirements.txt)

Problem src: [immutable.py](immutable.py)

Modified problem src: [immutable_local.py](immutable_local.py): RPC tweaked to
truffle node.  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2022/Lake/Immutable).