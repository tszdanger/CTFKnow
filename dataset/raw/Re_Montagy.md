# Re:Montagy

blockchain, 6 solves, 378 points

> Background:  
>  
> Hi there, I heard from my agent that many people ´_>` solved my challenge
> last year which was joyful.  
>  
> You might notice something when seeing this challenge name. And yes, last
> year's challenge was actually a part of this final art.  
>  
> A game started a year ago, lost between 0&1, come from the path and back
> through the shadow, will you catch the 'Montage' spirit?  
>  
> I'm waiting for you, from the past to the future.  
>  
> -- A. Monica  
>  
> Description:  
>  
> $ nc 54.176.60.63 10101  
>  
> [provided files](https://rwctf2021.s3-us-west-1.amazonaws.com/Re-
> Montagy_forplayers-f292511818d501e1d084faadfff71ece2837ae0e.tar)  
>  
> - Montagy.sol: the target contract  
> - Puzzle.sol: the contract deployed during newPuzzle  
>  
> Goal:  
>  
> Let the ETH balance of Montagy contract becomes 0.

## TL;DR

Use TEA equivalent keys to flip some opcodes and create backdoors, then find a
JOP chain.

## Background

This challenge, `Re:Montagy`, is the revenge version of `Montagy` in
RealWorldCTF 2019 Final. If you are not familiar with the previous challenge,
[this blog](https://x9453.github.io/2020/01/26/Real-World-CTF-
Finals-2019-Montagy/) is worth reading. `Montagy` is solved unintendedly, and
actually our solution to `Re:Montagy` is the only intended one during the
contest.

## Writeup

Two contracts' source code are provided, let's check `Montagy`'s first:

```solidity  
pragma solidity ^0.5.11;

contract Montagy{  
   address payable public owner;  
   mapping(bytes32=>uint256) registeredIDLength;  
   mapping(address=>bytes32) puzzleID;  
   ...  
   modifier onlyPuzzle(){  
       require(puzzleID[msg.sender] != 0);  
       _;  
   }

   function registerCode(bytes memory a) public onlyOwner {  
       registeredIDLength[tag(a)] = a.length;  
   }

   function newPuzzle(bytes memory code) public returns(address addr){  
       bytes32 id = tag(code);  
       require(registeredIDLength[id] == code.length);

       addr = deploy(code);  
       lastchildaddr = addr;  
       puzzleID[addr] = id;  
   }

   function solve(string memory info) public onlyPuzzle {  
       owner.transfer(address(this).balance);  
       winnerinfo = info;  
   }  
   ...  
   function tag(bytes memory a) pure public returns(bytes32 cs){  
       assembly{  
           let groupsize := 16  
           let head := add(a,groupsize)  
           let tail := add(head, mload(a))  
           let t1 := 0x21711730  
           let t2 := 0x7312f103  
           let m1,m2,m3,m4,p1,p2,p3,s,tmp  
           for { let i := head } lt(i, tail) { i := add(i, groupsize) } {  
               s := 0x6644498b  
               tmp := mload(i)  
               m1 := and(tmp,0xffffffff)  
               m2 := and(shr(0x20,tmp),0xffffffff)  
               m3 := and(shr(0x40,tmp),0xffffffff)  
               m4 := and(shr(0x60,tmp),0xffffffff)  
               for { let j := 0 } lt(j, 0x10) { j := add(j, 1) } {  
                   s := and(add(s, 0x68696e74),0xffffffff)  
                   p1 := sub(mul(t1, 0x10), m1)  
                   p2 := add(t1, s)  
                   p3 := add(div(t1,0x20), m2)  
                   t2 := and(add(t2, xor(p1,xor(p2,p3))), 0xffffffff)  
                   p1 := add(mul(t2, 0x10), m3)  
                   p2 := add(t2, s)  
                   p3 := sub(div(t2,0x20), m4)  
                   t1 := and(add(t1, xor(p1,xor(p2,p3))), 0xffffffff)  
               }  
           }  
           cs := xor(mul(t1,0x100000000),t2)  
       }  
   }  
}

```

The server makes three transactions. The first deploys `Montagy` with 0.1
ether. The second calls `registerCode` with the bytecode of contract `Puzzle`.
Finally `newPuzzle` is called with the same parameter, and `Puzzle` is
deployed.

Our goal is to empty the balance of contract `Montagy`, and the only way is
calling `solve` from the puzzle it deployed. Let's check `Puzzle`'s source
code now:

```solidity  
pragma solidity ^0.5.11;

contract Puzzle{  
   ...  
   function loose() view public returns(bool){  
       uint256 t1 = (a^b^c)+(d^e^f)+(g^h^i);  
       uint256 t2 = (a+d+g)^(b+e+h)^(c+f+i);  
       require(t1 + t2 < 0xaabbccdd);  
       require(t1 > 0x8261e26b90505061031256e5afb60721cb);  
       require(0xf35b6080614321368282376084810151606401816080016143855161051756 >= t1*t2);  
       require(t1 - t2 >= 0x65e670d9bd540cea22fdab97e36840e2);  
       return true;  
   }  
   function harsh(bytes memory seed, string memory info) public{  
       require(loose());  
       if (keccak256(seed) == bytes32(bytes18(0x6111d850336107ef16565b908018915a9056))) {  
           server.solve(info);  
       }  
   }  
}  
```

Though we can find answers to `loose()`, it is impossible to pass the
keccak256 challenge. The `Puzzle` is unsolvable! Noticing we can call
`newPuzzle` to deploy other puzzles as long as the length and `tag` matches,
let's dive into the `tag` function.

The `tag` function implements TEA to compress/hash the input. It encrpts `t1`
and `t2` continuously with `input[16*i:16*(i+1)]` as keys. A quick diff shows
that `lt(j, 0x10)` was `lt(j, 0x4)` in the previous challenge, suggesting that
bruteforcing the tag may not be the intended solution (although other teams
still managed to do so).

TEA suffers from equivalent keys. In `tag` function, the 16 bytes of key is
separated into `m1~m4`, 4 bytes each. If we flip the MSB of both `m1` and
`m2`, or both `m3` and `m4`, or all the four, the encryption result won't
change, therefore we can change some pairs of opcodes of  `Puzzle` without
changing the `tag`. To be more specfic, the pairs should be located at
`0x...0` and `0x...4`, or `0x...8` and `0x...c`. Then the question is where to
change?

The consts in `Puzzle` seems weird, why not try disassembling them?

```text  
000002F0 PUSH17 0x8261e26b90505061031256e5afb60721cb ->  
[0] DUP3  
[3] PUSH2 0xe26b  
[4] SWAP1  
[5] POP  
[6] POP  
[9] PUSH2 0x0312  
[10] JUMP  
[11] 'e5'(Unknown Opcode)  
[12] 'af'(Unknown Opcode)  
[13] 'b6'(Unknown Opcode)  
[14] SMOD  
[15] '21'(Unknown Opcode)  
[16] 'cb'(Unknown Opcode)

00000310 PUSH31
0xf35b6080614321368282376084810151606401816080016143855161051756 ->  
[0] RETURN  
[1] JUMPDEST  
[3] PUSH1 0x80  
[6] PUSH2 0x4321  
[7] CALLDATASIZE  
[8] DUP3  
[9] DUP3  
[10] CALLDATACOPY  
[12] PUSH1 0x84  
[13] DUP2  
[14] ADD  
[15] MLOAD  
[17] PUSH1 0x64  
[18] ADD  
[19] DUP2  
[21] PUSH1 0x80  
[22] ADD  
[25] PUSH2 0x4385  
[26] MLOAD  
[29] PUSH2 0x0517  
[30] JUMP

0000033B PUSH16 0x65e670d9bd540cea22fdab97e36840e2  
junk

00000374 PUSH18 0x6111d850336107ef16565b908018915a9056 ->  
[2] PUSH2 0x11d8  
[3] POP  
[4] CALLER  
[7] PUSH2 0x07ef  
[8] AND  
[9] JUMP  
[10] JUMPDEST  
[11] SWAP1  
[12] DUP1  
[13] XOR  
[14] SWAP2  
[15] GAS  
[16] SWAP1  
[17] JUMP  
```

Amazing! And the `PUSH` opcode before the consts are located at somewhere we
can flip, a strong hint that we are on the right track! (except the useless
third)

The controll flow changes. When we reach the line `require(t1 >
0x8261e26b90505061031256e5afb60721cb)`, we will jump to `0x0312`, which is
`JUMPDEST` in the second backdoor, then some part of our calldata is copied to
the memory. Then we jump to `0x0517`, which takes some 2-byte pieces from our
calldata to the stack, then jump to the first piece. Now we can controll the
next JOP(Jump Oriented Programming) destination.

After flipping, `00000374 PUSH18(71)` becomes `CALL(F1)`. Now there are two
`CALL` opcodes. First we attempted to use the original one, but all trials
failed (either fail to pass the keccak check, or end up with an uncontrollable
jump address). Everything is clearer when we decide to make full use of the
backdoors, including the flipped `CALL`. We have `0x049E` gadget to load the
`Montagy` address from storage, and the `00000374` backdoor to load gas
(second half) and make the `CALL` (first half). Other params for `CALL` have
been already prepared, and the calling data is what `0x0312` has copied.

Finally after the `CALL`, the pseudocode is `JUMP(msg.sender&0x07ef)`. We can
find accounts to land at `JUMPDEST; STOP` to finish the execution.

Then comes the flag!
`rwctf{rE7uRn_2_FuTuR3_w1Th_1_cUp_f0_T_f70M_7He_P4s7_THATs_C4l13d_M0N74GY!}`

## exploit

Nope. My exploit is ugly and contains a lot of private keys, and I'm too lazy
to tidy things up. However, you may try to find my exploit transactions on
rinkeby and reproduce it lol.

Original writeup
(https://github.com/0ops/ctfs-2021/tree/main/RealWorldCTF/Re_Montagy).