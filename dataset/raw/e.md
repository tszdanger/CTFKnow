# BraekerCTF 2024

## e

> "Grrrrr". This robot just growls. The other bots tell you that it is angry
> because it can't count very high. Can you teach it how?  
>  
>  Author: spipm  
>  
> [`e.cpp`](https://raw.githubusercontent.com/D13David/ctf-
> writeups/main/braekerctf24/misc/e.cpp)

Tags: _misc_

## Solution  
We get a small c++ that does three stages of tests and gives us the flag if we
succeed all stages.

So, lets tackle this one by one:

```c++  
bool flow_start() {

	// Get user input  
	float a = get_user_input("Number that is equal to two: ");

	// Can't be two  
	if (a <= 2)  
		return false;

	// Check if equal to 2  
	return (unsigned short)a == 2;  
}  
```

The user input is stored as float and then cast to an `unsigned short`. Here
we can use the integer overflow at 16-bit to get back to value `2`. Passing in
`65538` will overflow the maximum value by 3 (0xffff-65538 = -3) giving us the
value 2.

```bash  
$ nc 0.cloud.chals.io 30531  
Welcome!  
Number that is equal to two:  
65538  
Well done! This is the second round:  
```

Lets move on to the second stage.

```c++  
bool round_2() {

	float total = 0;

	// Sum these numbers to 0.9  
	for (int i = 0; i < 9; i++)  
		total += 0.1;

	// Add user input  
	total += get_user_input("Number to add to 0.9 to make 1: ");

	// Check if equal to one  
	return total == 1.0;  
}  
```

This is a typical precision issue. Mathematically we need to add `0.1` but
that will overshoot by a tiny amount giving us something line ~`1.00000012`.
We rather give `0.0999999` to get to the sum of `1.0`.

```bash  
Number to add to 0.9 to make 1:  
0.0999999  
Great! Up to level three:  
```

Perfect, now for the last stage.

```c++  
bool level_3() {

	float total = 0;

	unsigned int *seed;  
	vector<float> n_arr;

	// Random seed  
	seed = (unsigned int *)getauxval(AT_RANDOM);  
	srand(*seed);

	// Add user input  
	add_user_input(&n_arr, "Number to add to array to equal zero: ");

	// Add many random integers  
	for (int i = 0; i < 1024 * (8 + rand() % 1024); i++)  
		n_arr.push_back((rand() % 1024) + 1);

	// Add user input  
	add_user_input(&n_arr, "Number to add to array to equal zero: ");

	// Get sum  
	for (int i = 0; i < n_arr.size(); i++)  
		total += n_arr[i];

	// Check if equal to zero  
	return total == 0;  
}  
```

Here we can specify two numbers. After the first number a random number of
float values is put into an array. After this we can specify a final number.
The test succeeds if the sum of all the numbers is `0`. Since there is no way
to know what the sum of the random numbers is we have to find another way.
Thankfully we can squeeze the faily small values (range between 1 and 1024) by
just specifying a very big value at the beginning and a big negative value at
the end. This rendering the random values pretty much without any impact and
leading to the sum of zero.

```bash  
Number to add to array to equal zero:  
30000000000  
Number to add to array to equal zero:  
-30000000000  
Well done! Here is the flag: brck{Th3_3pS1l0n_w0rkS_In_M15t3riOuS_W4yS}  
```

Flag `brck{Th3_3pS1l0n_w0rkS_In_M15t3riOuS_W4yS}`

Original writeup (https://github.com/D13David/ctf-
writeups/blob/main/braekerctf24/misc/README.md).# e  
**Category:** Cryptography

**Points:** 144

**Description:**  
> n =
> 0x5fb76f7f36c0d7788650e3e81fe18ad105970eb2dd19576d29e8a8697ebbd97f4fc2582bf1dc53d527953d9615439ca1b546b2fc1cd533db5fce6f72419f268e3182c0324a631a17d6b3e76540f52f2df51ca34983392d274f292139c28990660fa0e23d1b350da7aa7458a3783107a296dcd1720e32afb431954d8896f0587cd1c8f1d20701d6173b7cffe53679ebda80f137c83276d6628697961f5fcd39e18316770917338c6dc59a241dcdc66417fed42524c33093251c1d318b9dbeb6c3d0a69438b875958e8885d242d196e25bc73595e7f237c8124e07a79f7066f2dee393e2130306ba29e7ece1825798ff8b35416b3a0d96bcdc6eca5616ea2874954f8f88232450ddad3e109338bcc5d84e7b592a6b0871bd4130b84f81ed188e9d5495c8545aa8dea2b65e8605f5a49e3a1c221cbcc301665187658784a8f42a23c2ca2572477ba56ff19934019b48f5a1ab8a50626c85bdd476b11e8c1fb0b740c2370de3da5cc06371a7aa2c4e12eee3dc4cda07a8c84ba2bc3ee2017156468af95111d7ee5152ce35e66fa027a944b43c27fbd27faa5b4f9075be3526a7a5be8a533b523cd5c738c724e97597fc2e3666cfcad7c79d972ff8d9572100e860395cdc3761af3f4cc225a6df83a55802723f95cfba5918d83913f2cc9b219210249928c291310d449042772e2d0a50620d666a137f79770de6f10196b30cc756e1  
>  
> e = 0b1101  
>  
> c =
> 0x6003a15ff3f9bc74fcc48dc0f5fc59c31cb84df2424c9311d94cb40570eeaa78e0f8fc2917addd1afc8e5810b2e80a95019c88c4ee74849777eb9d0ee27ab80d3528c6f3f95a37d1581f9b3cd8976904c42f8613ee79cf8c94074ede9f034b61433f1fef835f2a0a45663ec4a0facedc068f6fa2b534c9c7a2f4789c699c2dcd952ed82180a6de00a51904c2df74eb73996845842276d5523c66800034351204b921d4780180ca646421c61033017e4986d9f6a892ed649c4fd40d4cf5b4faf0befb1e2098ee33b8bea461a8626dd8cd2eed05ccd471700e2a1b99ed347660cbd0f202212f6c0d7ad8ef6f878d887af0cd0429c417c9f7dd64890146b91152ea0c30637ce503635018fd2caf436a12378e5892992b8ec563f0988fc0cebd2926662d4604b8393fb2000

## Writeup  
Here we are given a public exponent of 13, a ciphertext, and a modulus (both
in hex).  
I don't like looking at hex for RSA, so I converted it to decimal:  
```  
n =
390489435257757050962694900628597750000579222652331667618284165302943905225288969762176855801097841580556025206135063119377780258773946551477397214530192584542559975339905571052158012999468964332437424628306511823269722453860362280496202533043021337796709339953817006833706504476313712943965322096302491056783227523784482002015145826987110574460307401934641874704050677704711801356268639773155081360828180903299964526589331336235306332567448562160526113866018006123967625576962689761521605387494709446518692462619862696168918816662536077370130661612070397479668829129920065326461187098803231397068051063929181738677526073658243869002572485447843169095810970975008795690074220899938136361892311637145808179133421447144085978655477817360358554032010516385983131407000011685574404126645116055363989608798299433959920227740092093920293556264000720381725702113290830326487540883170568741677111457568414739635182616494007311080902460736310863610217949372424386793484900002898788953599811705062201758177232830116056373978679467452122685972908266494259227709026880378075787599801726114638151543214172984729176207988155050429283715199503476101477015502266718187756254132831832109660502543721206835505701564820158859089751904108288138208040673  
e = 13  
c =
106043754914029053332380422656979154558759375897122425881860894698990092522305749145737374365974220063939891079764890878154070613914922418958583544498027475665662636594704078148882769433156473437121146773425968949033386468829167234570619323371997036112007508384568510674710537942785775371160931981856023034244395378977429902662365257811359886125721032794417995359223839236947456899351021253568576347533100384607077413225615309141290386668460232755119696828398399706666171431603664375206400701950963668907213087581791373592734473983283263803333104246685774546585505902951125395519774268152638482568171628156316175459200284173273491875899659385136852897094442953202427686882030389289946251863304968551409170000000000000  
```

I noticed how small the e was and figured that it might be a possibility to
take the  
13th root of this ciphertext instead of finding the private exponent and
decrypting  
from there. Giving it a shot in python3 and a little help from  gmpy2, I came
up with:  
```  
from Crypto.Util.number import long_to_bytes  
from pwn import *  
import gmpy2

c =
10604375491402905333238042265697915455875937589712242588186089469899009252230574914573737436597422006393989107976489  
087815407061391492241895858354449802747566566263659470407814888276943315647343712114677342596894903338646882916723457061  
932337199703611200750838456851067471053794278577537116093198185602303424439537897742990266236525781135988612572103279441  
799535922383923694745689935102125356857634753310038460707741322561530914129038666846023275511969682839839970666617143160  
366437520640070195096366890721308758179137359273447398328326380333310424668577454658550590295112539551977426815263848256  
817162815631617545920028417327349187589965938513685289709444295320242768688203038928994625186330496855140917000000000000  
0

plain, extra = gmpy2.iroot(c, 13)  
flag = long_to_bytes(plain).decode()  
log.info("Flag: {}".format(flag))  
log.success("Actual Flag: {}".format(flag[::-1]))  
```

**Output:**  
```  
$ python3 e.py  
[*] Flag: }31_rebmun_ykcul{FTCbgr  
[+] Actual Flag: rgbCTF{lucky_number_13}  
```

## Flag  
rgbCTF{lucky_number_13}

## Resources  
[RSA Info](https://en.wikipedia.org/wiki/RSA_(cryptosystem))  

Original writeup
(https://github.com/itsecgary/CTFs/tree/master/rgbCTF%202020/e).