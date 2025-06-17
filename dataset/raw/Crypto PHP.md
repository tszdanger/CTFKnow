# Crypto PHP

No GPU Cores Will Be Harmed in the Solving of This Challenge!

Url: http://gold.razictf.ir/PleaseCreateABitcoinAddressForMe/

Tags: web security

## Solution

We are greeted with `I'm not giving you any flags!`. Looking at the source:

```

I'm not giving you any flags!  
```

We download the `index.php.bak`:

```php  
<?php

function checkAddress($address)
{
    $origbase58 = $address;
    $dec = "0";

    for ($i = 0; $i < strlen($address); $i++)
    {
        $dec = bcadd(bcmul($dec,"58",0),strpos("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",substr($address,$i,1)),0);
    }

    $address = "";

    while (bccomp($dec,0) == 1)
    {
        $dv = bcdiv($dec,"16",0);
        $rem = (integer)bcmod($dec,"16");
        $dec = $dv;
        $address = $address.substr("0123456789ABCDEF",$rem,1);
    }

    $address = strrev($address);

    for ($i = 0; $i < strlen($origbase58) && substr($origbase58,$i,1) == "1"; $i++)
    {
        $address = "00".$address;
    }

    if (strlen($address)%2 != 0)
    {
        $address = "0".$address;
    }

    if (strlen($address) != 50)
    {
        return false;
    }

    if (hexdec(substr($address,0,2)) > 0)
    {
        return false;
    }

    return substr(strtoupper(hash("sha256",hash("sha256",pack("H*",substr($address,0,strlen($address)-8)),true))),0,8) == substr($address,strlen($address)-8);
}

$address = "35hK24tcLEWcgNA4JxpvbkNkoAcDGqQPsP";
if (isset ($_GET["PleaseCreateABitcoinAddressForMe"]))
{
$address = $_GET["PleaseCreateABitcoinAddressForMe"];
}

$check = checkAddress($address);
if ($check)
{
	if (substr( $address, 0, 5 ) === "1Razi")
	{
		echo "flag";
	}
}
else
{
	echo "I'm not giving you any flags!";
}

echo $check;

?> 
```

We can provide an address through the get parameter
`PleaseCreateABitcoinAddressForMe`. It's checked via `checkAdress` which has
to return true in order to continue. The provided address has to start with
`1Razi`.

Let's analyze what `checkAdress` does. It uses `bcmath` for arbitrary
precision calculations. We iterate over the chars of the address and add that
to the result of `bcmul($dec, "58", 0)`. After that we have a very large
number. Like the first variable name `origbase58` implies, this is base58 ->
decimal.

If you want to restore the next step it in python, you need the fractions
module, because python converts these numbers to `bignumber`:

```python  
>>> n = 42468160281214442798985882180071997964045162989719209072  
>>> int(n / 16)  
2654260017575902720967102997974858231782517263919218688  
>>> (Fraction(n) / 16).numerator  
2654260017575902674936617636254499872752822686857450567  
>>> int(n / 16) % 16  
0  
>>> (Fraction(n) / 16 % 16).numerator  
7  
```

It converts our number from decimal to a hexadecimal string. So you don't
actually need it but to initally understand what it is doing it might be
helpful.

```python  
>>> dec = n  
>>> hexchars = "0123456789ABCDEF"  
>>> addr = ""  
>>> while dec > 0:  
...         dv, rem = divmod(dec, 16)  
...         dec = Fraction(dv)  
...         addr += hexchars[rem.numerator]  
...  
>>> addr[::-1]  
'1BB63666D1882FDD5ED9DA658AFAF56502193C397E54470'  
>>> hex(n)[2:].upper()  
'1BB63666D1882FDD5ED9DA658AFAF56502193C397E54470'  
```

The string is additionally padded with zeros for starting 1s in the address
and if the length is odd. The length has to be 50 afterwards and the first two
chars (1 byte) has to be zero. Since the required address already starts with
a 1 that is converted to zeros this is no problem.

Let's summarize: our adress is converted like this: base58 -> decimal ->
hexadecimal string.

### The mistake

The last part is hard to read, storing results in variables we can now see:

```php  

Original writeup (https://github.com/klassiker/ctf-
writeups/blob/master/2020/razictf/crypto-php.md).