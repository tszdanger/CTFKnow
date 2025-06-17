# Invisible Maze (misc/re, 936p, 13 solved)

## Description

In the task we get a [gameboy game
rom](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-31-InCTF/maze/output.gb).  
The game is just moving around with a sprite of a flag.  
The intro says you will get the flag if you place the flag in the right
location.

## Analysis

### Blackbox

We almost managed to solve this just by strings+blackbox crypto approach,
because there is:

```  
KRUHZ=...!R.!0...RX!.:!>.PX.?.Way to go! . flg if u not noob: %s  
```

Our first guess (and rightly so!) was that the string before `Way to go!` is
in fact encrypted flag.  
But it wasn't just a simple XOR, and we didn't want to spend too much time
trying to blindly bash it (although I'm pretty sure we would have got it,
considering how simple it was).

### Actual reversing

We started off by dropping https://github.com/Gekkio/GhidraBoy into Ghidra to
get started.

There are some weird functions and also a rickroll youtube link as troll.

The really interesting part is that there are no x-refs to the `Way to go`
string, and we expect to see that in some flag printing function.  
We guessed that Ghidra didn't mark some code parts yet and we need to look
around.  
If we knew how addressing in GB works, maybe we could just look for the
address of this constant...  
We go through the disasm looking for unmarked regions which look like code.  
It's not a big binary, so we finally find, right below entry point function,
at `0x0200`:

```c  
void flag_print(byte param_1,byte param_2)  
{  
 byte index_00;  
 short index;  
 byte bStack0005;  
  
 index = 0;  
 while ((bStack0005 ^ 0x80) < 0x80 || (byte)((bStack0005 ^ 0x80) + 0x80) <
(index_00 < 0x1d)) {  
   DAT_c1a0 = (undefined)((ushort)(&KRUHZ= + index) >> 8);  
   DAT_c19f = (&KRUHZ=)[index] + param_1;  
   (&decrypted_flag)[index] = param_2 ^ DAT_c19f;  
   index = index + 1;  
 }  
 (&decrypted_flag)[index] = 0;  
 FUN_1658("Way to go! \n flg if u not noob: %s\n",&decrypted_flag);  
 return;  
}  
```

## Solution

Once we know how the decryption works, we can easily break it.  
It gets only 2 secret values, so we could brute-force it:

```python  
def main():  
   data = "4B 52 55 48 5A 3D 03 09 07 21 52 04 21 30 05 0A 05 52 58 21 04 3A
21 3E 05 50 58 08 3F".replace(" ", "").decode("hex")  
   for plus in range(256):  
       for x in range(256):  
           res = "".join([chr(((ord(c) + plus) ^ x) & 0xff) for c in data])  
           if 'inctf' in res:  
               print(plus, x, res)

main()  
```

And we get the flag: `inctf{175_n0_L363nd_0F_z3ld4}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-07-31-InCTF/maze/README.md).