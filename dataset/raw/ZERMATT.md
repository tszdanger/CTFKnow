# Google CTF 2023

## ZERMATT

> Roblox made lua packing popular, since we'd like to keep hanging out with
> the cool kids, he's our take on it.  
>  
>  Author: N/A  
>  
> [`attachment.zip`](https://github.com/D13David/ctf-
> writeups/blob/main/googlectf23/rev/zermatt/attachment.zip)

Tags: _rev_

## Solution  
For this challenge a lua script is provide. After opening it's obvious the
script is obfuscated in various ways. When executed a banner is displayed and
the user is prompted for input. The input seems to be validated and a message
`LOSE` is displayed. Probably entering the flag would be a `WIN`.

```  
$ lua zermatt.lua  
_____             _     ___ _____ ____  
|   __|___ ___ ___| |___|   |_   _|  __|  
|  |  | . | . | . | | -_| -<  | | |  __|  
|_____|___|___|_  |_|___|___| |_| |_|  
             |___|       ZerMatt - misc  
> asdasdasd  
LOSE  
```

To get a better overview we run a beautifier on the script to have at least
sane formatting.

```bash  
lua-format --column-limit=1000 zermatt.lua > zermatt1.lua  
```

The script is still very much unreadable. There are a few obfuscation
techniques that need to be reversed. For one strings are encoded like

```lua  
local v8 = _G[v7("\79\15\131\30\40\13\20\203",
"\59\96\237\107\69\111\113\185")];  
   local v9 = _G[v7("\55\2\190\232\63\247",
"\68\118\204\129\81\144\122")][v7("\12\180\100\225",
"\110\205\16\132\107\85\33\139")];  
   local v10 = _G[v7("\243\205\101\215\89\95",
"\128\185\23\190\55\56\100")][v7("\240\94\174\46",
"\147\54\207\92\126\115\131")];  
```

The function to decode is already present `v7`, so we can just use this
function to decode the strings. Also we rename the function to `concatString`
and also clean up the code a bit.

```lua  
local function concatString(part1, part2)  
   local result = {};  
   for i = 1, #part1 do table.insert(result,
string.char(bit32.bxor(string.byte(string.sub(part1, i, i + 1)),
string.byte(string.sub(part2, 1 + ((i - 1) % #part2), 1 + ((i - 1) % #part2) +
1))) % 256)); end  
   return table.concat(result);  
end  
```

After decoding the strings we replace the variables `v8`, `v9`, `v10`, ...
with the associated function names within the script. This already brings a
tiny bit of readability. But there is still more to clean up.

One specific pattern is used over and over. The progam flow is broken down
into small sections and executed like a state machine. This is easy, although
quite annoying, to clean up.

```lua  
local v291 = 0;  
local v292;  
local v293;  
while true do  
   if (v291 == 0) then  
       v292 = 0;  
       v293 = nil;  
       v291 = 1;  
   end  
   if (v291 == 1) then  
       while true do  
           if (v292 == 0) then  
               v293 = v193[(6419 - 5004) - (98 + 349 + 966)];  
               v191[v293](v21(v191, v293 + (978 - (553 + 424)), v159));  
               break  
           end  
       end  
       break  
   end  
end  
```

After removing the outer state blocks and then the inner state blocks the code
is getting shorter.

```lua  
v292 = 0;  
v293 = nil;  
while true do  
   if (v292 == 0) then  
       v293 = v193[(6419 - 5004) - (98 + 349 + 966)];  
       v191[v293](v21(v191, v293 + (978 - (553 + 424)), v159));  
       break  
   end  
end  
```

```lua  
v293 = v193[(6419 - 5004) - (98 + 349 + 966)];  
v191[v293](v21(v191, v293 + (978 - (553 + 424)), v159));  
```

After going through the `1870` or so lines the code was condensed to under
`400` lines of code. Also the code blocks where now sorted in the right order
so that the code was quite readable and nearly ready for inspection. One last
thing remaing was the obfuscated numeric literals á la `(6419 - 5004) - (98 +
349 + 966)`. This could be easily replaced with the resulting value.

```lua  
v293 = v193[2];  
v191[v293](v21(v191, v293 + 1), v159);  
```

Next up, inspecting the code and trying to understand bits and pieces.
Renaming here and there a function or variable, and trying to get as much info
as possible out of the code. A couple of small functions are present for
reading bytes, shorts, longs, strings, ... from a byte stream as as a few
other functionality. After giving the functions readable names more and more
bits of the code started to make sense. The code flow is something like this.

Starting with `main`, the main function is called with a long string and the
global table. The string is compressed with a basic RLE compression. In `main`
the string is decompressed as a first step.

```lua  
-- basic RLE decompression of payload  
local repeatCount = nil;  
payloadBuffer = string.gsub(string.sub(payloadBuffer, 5), "..", function(v86)  
   -- if pair ends with 'O' first part is the repeat length  
   if (string.byte(v86, 2) == 79) then  
       repeatCount = tonumber(string.sub(v86, 1, 1));  
       return "";  
   else  
       local currentByte = string.char(tonumber(v86, 16));  
       if repeatCount then  
           local currentByteRepeated = string.rep(currentByte, repeatCount);  
           repeatCount = nil;  
           return currentByteRepeated;  
       else  
           return currentByte;  
       end  
   end  
end);  
```

A decompressed dump of the payload can be found
[`here`](https://github.com/D13David/ctf-
writeups/blob/main/googlectf23/rev/zermatt/output.bin). After this the buffer
is further processed and then passed to another function. After staring at
both functions for a while it turned out that the second function is basically
a VM executing some bytecode, which is used in the first function. Therefore
the functions are named `loadImage` and `run`.

```lua  
function loadImage()  
   local codeSegment = {};  
   local subPrograms = {};  
   local v58 = {};  
   local result = {codeSegment, subPrograms, nil, v58};  
  
   local dataTableSize = readInt();  
   local dataTable = {};  
   for i = 1, dataTableSize do  
       local valueType = readByte();  
       local value = nil;  
       if (valueType == 1) then  
           value = readByte() ~= 0;  
       elseif (valueType == 2) then  
           value = readFloat();  
       elseif (valueType == 3) then  
           value = readByteArray();  
       end  
       dataTable[i] = value;  
   end

   result[3] = readByte();  
   for i = 1, readInt() do  
       local bitPackedValue = readByte();  
       if (valueForBitRange(bitPackedValue, 1, 1) == 0) then  
           local bits2_3 = valueForBitRange(bitPackedValue, 2, 3);  
           local bits4_6 = valueForBitRange(bitPackedValue, 4, 6);  
           local opcode = {readShort(), readShort(), nil, nil};   
           if (bits2_3 == 0) then  
               opcode[3] = readShort();  
               opcode[4] = readShort();  
           elseif (bits2_3 == 1) then  
               opcode[3] = readInt();  
           elseif (bits2_3 == 2) then  
               opcode[3] = readInt() - 65536;  
           elseif (bits2_3 == 3) then  
               opcode[3] = readInt() - 65536;  
               opcode[4] = readShort();  
           end  
           if (valueForBitRange(bits4_6, 1, 1) == 1) then opcode[2] = dataTable[opcode[2]]; end  
           if (valueForBitRange(bits4_6, 2, 2) == 1) then opcode[3] = dataTable[opcode[3]]; end  
           if (valueForBitRange(bits4_6, 3, 3) == 1) then opcode[4] = dataTable[opcode[4]]; end  
           codeSegment[i] = opcode;  
           --printOpcode(i, opcode);  
       end  
   end  
  
   for i = 1, readInt() do subPrograms[i - 1] = loadImage(); end  
   for i = 1, readInt() do v58[i] = readInt(); end  
   return result;  
end

function run(image, stack, global)  
-- ...  
end

-- snip main

return run(loadImage(), {}, v29)(...);  
```

The first thing that is loaded is a list of constants. The first 4 bytes
specify the size of the table and then there is one entry per constant
containing a type (1 byte) and depending of the type the type value. Three
types could be found `byte`, `float` and `string`. The dump of the constant
list can be seen here:

```  
Constant Table =======================================  
01: (s): string  
02: (s): char  
03: (s): byte  
04: (s): sub  
05: (s): bit32  
06: (s): bit  
07: (s): bxor  
08: (s): table  
09: (s): concat  
10: (s): insert  
11: (s): io  
12: (s): write  
13: (s):  _____             _     ___ _____ ____ 0a  
14: (s): |   __|___ ___ ___| |___|   |_   _|  __|0a  
15: (s): |  |  | . | . | . | | -_| -<  | | |  __|0a  
16: (s): |_____|___|___|_  |_|___|___| |_| |_|   0a  
17: (s):               |___|       ZerMatt - misc 0a  
18: (s): @91  
19: (s): ~b1a3bbE86dba7  
20: (s): s  
21: (s): read  
22: (s):
df17eb1e4e81cc1/c4ef7f2#d1c34cc9faf2,d915c4c3!d4>c0ff,c9/fafe"de/faef"c3.c7f3;f2/d6ff"dd/d8  
23: (s): 9cCadJa5  
24: (s): print  
25: (s): q1d99  
26: (s): &Td7)vdcF  
27: (s): d27f%07  
28: (s): 9e0vBr  
```

Afterwards the opcodes are parsed. The number of opcodes is specified by an 4
bytes integer and then every opcode has a `code` so the interpreter knows how
to handle the opcode and three parameters that can be used as command input
(like target register index, memory address, constant, ...). A packed value
specify which parameters are initialized and how they are stored. Bit 1-2 are
specifying the type of the parameters. For instance, `type 0` reads two shorts
for parameters 2 and 3, while `type 1` reads a long for parameter 2 only.

Bits 3-5 then specify if a parameter is resolved with the constant table, for
instance are an index to a function name or any other text.

In the last step potential other programs are loaded which have the same
format, starting with a constant table etc...

The `run` function then basically executes the opcode list. Some more cleanup
was needed since the functionality was too nested. One thing to point out is,
that run does not immediately run the code but returns a function pointer that
can be stored within memory and executed by following commands.

```lua  
_G['A'], _G['B'] = createTableAndCount(pcall(v162));  
if not _G['A'][1] then  
   local v183 = image[4][currentInstruction] or "?";  
   error("Script error at [" .. v183 .. "]:" .. _G['A'][2]);  
else  
   return table.unpack(_G['A'], 2, _G['B']);  
end  
```

The function calls another local function `v162` which is the VM. `v162` first
initializes the memory with parameters passed to the program and then has a
big loop where command execution happens.

```lua  
for i = 0, countOfArguments do  
   if (i >= v69) then  
       v189[i - v69] = v160[i + 1];  
   else  
       mem[i] = v160[i + 1];  
   end  
end  
while true do  
   local op = codeSegment[currentInstruction];  
   local opcodeType = op[OP_TYPE];  
   if (opcodeType == 0) then  
       return table.unpack(mem, op[OP_PARAM1], loadedTableSize);  
   elseif (opcodeType == 1) then  
       mem[op[OP_PARAM1]] = mem[op[OP_PARAM2]] - op[OP_PARAM3];  
   elseif (opcodeType == 2) then  
       mem[op[OP_PARAM1]] = mem[op[OP_PARAM2]] % op[OP_PARAM3];  
   elseif (opcodeType == 3) then  
       currentInstruction = op[OP_PARAM2];  
   elseif (opcodeType == 4) then  
       if (mem[op[OP_PARAM1]] == mem[op[OP_PARAM3]]) then  
           currentInstruction = currentInstruction + 1;  
       else  
           currentInstruction = op[OP_PARAM2];  
       end  
   else  
   -- snip  
end  
```

So, running the script will decode the program image and execute the image.
Doing so and dumping `_G['A']` will give us the flag, since the program is
decoding the flag and storing it in memory. But this would be cheating, right?

To get a better understanding on what the program is doing the assembly of a
run can be dumped with some debugging information. This is quite easy, just a
big function dumping info for every opcode.

```lua  
function printOpcode(addr, op)  
   io.write(string.format("\n%04x: ", addr));  
   local opcodeType = op[OP_TYPE];  
   if (opcodeType == 0) then  
       io.write("RET "); io.write(string.format("\t%d #tblcnt", op[OP_PARAM1]))  
   elseif (opcodeType == 1) then  
       io.write("SUB "); io.write(string.format("\t[%d], [%d] %d", op[OP_PARAM1], op[OP_PARAM2], op[OP_PARAM3]));  
   elseif (opcodeType == 2) then  
       io.write("MOD "); io.write(string.format("\t[%d], [%d] %d", op[OP_PARAM1], op[OP_PARAM2], op[OP_PARAM3]));  
   elseif (opcodeType == 3) then  
       io.write("JMP "); io.write(string.format("\t%04x", op[OP_PARAM2]));  
   --- snip  
end  
```

Doing this gives a full trace of the program execution. A small part is shown
here in this article, the full trace can be found
[`here`](https://github.com/D13David/ctf-
writeups/blob/main/googlectf23/rev/zermatt/zermatt_trace.txt).

First some functions are loaded into memory and the only subroutine is
initialized with the same set of functionality.  
```  
0001: OBJ       [0], G['string']  
0002: LOAD      [0], char               (table): ???  
0003: OBJ       [1], G['string']  
0004: LOAD      [1], byte               (table): ???  
0005: OBJ       [2], G['string']  
0006: LOAD      [2], sub                (table): ???  
0007: OBJ       [3], G['bit32']  
0008: JE        000a, [3]               (table): ???  
000b: LOAD      [4], bxor               (table): ???  
000c: OBJ       [5], G['table']  
000d: LOAD      [5], concat             (table): ???  
000e: OBJ       [6], G['table']  
000f: LOAD      [6], insert             (table): ???  
0010: LOAD      [7], 0                           0 mem[6] (f): table.insert 1
mem[0] (f): string.char 2 mem[4] (f): bit32.bxor 3 mem[1] (f): string.byte 4
mem[2] (f): string.sub 5 mem[5] (f): table.concat  
```

Then the banner is printed.  
```  
0017: OBJ       [8], G['io']  
0018: LOAD      [8], write              (table): ???  
0019: MOV       [9], (s):
205f5f5f5f5f202020202020202020202020205f20202020205f5f5f205f5f5f5f5f205f5f5f5f200a  
001a: CALL      8               (s):  _____             _     ___ _____ ____
0a  _____             _     ___ _____ ____

001b: OBJ       [8], G['io']  
001c: LOAD      [8], write              (table): ???  
001d: MOV       [9], (s):
7c2020205f5f7c5f5f5f205f5f5f205f5f5f7c207c5f5f5f7c2020207c5f2020205f7c20205f5f7c0a  
001e: CALL      8               (s): |   __|___ ___ ___| |___|   |_   _|  __|0a |   __|___ ___ ___| |___|   |_   _|  __|  
001f: OBJ       [8], G['io']  
0020: LOAD      [8], write              (table): ???  
0021: MOV       [9], (s):
7c20207c20207c202e207c202e207c202e207c207c202d5f7c202d3c20207c207c207c20205f5f7c0a  
0022: CALL      8               (s): |  |  | . | . | . | | -_| -<  | | |  __|0a |  |  | . | . | . | | -_| -<  | | |  __|  
0023: OBJ       [8], G['io']  
0024: LOAD      [8], write              (table): ???  
0025: MOV       [9], (s):
7c5f5f5f5f5f7c5f5f5f7c5f5f5f7c5f20207c5f7c5f5f5f7c5f5f5f7c207c5f7c207c5f7c2020200a  
0026: CALL      8               (s): |_____|___|___|_  |_|___|___| |_| |_|
0a |_____|___|___|_  |_|___|___| |_| |_|

0027: OBJ       [8], G['io']  
0028: LOAD      [8], write              (table): ???  
0029: MOV       [9], (s):
20202020202020202020202020207c5f5f5f7c202020202020205a65724d617474202d206d697363200a  
002a: CALL      8               (s):               |___|       ZerMatt - misc
0a               |___|       ZerMatt - misc  
002b: OBJ       [8], G['io']  
002c: LOAD      [8], write              (table): ???  
```

This part is interesting as it involves calling the subroutine (in register
`7`) with two byte array `4091` and `7eb1a3bb4586dba7`. The values are loaded
to the registers right after the function and `LDTBL1` calls the function and
passes the argument table to the function.  
```  
002d: MOV       [9], [7]                (f): unknown  
002e: MOV       [10], (s): 4091  
002f: MOV       [11], (s): 7eb1a3bb4586dba7  
0030: LDTBL1    [9], 10 11              (s): 4091 (s): 7eb1a3bb4586dba7  
```

This is the function that is called. It basically is used to decrypt the
string passed as parameter. The algorithm is a simple `xor` with a given key.  
```  
0001: TABLE     [2]
-- create new table  
0002: MOV       [3], (n): 1  
0003: LDCNT     [4] #[0]                (n): 2
-- length of encrypted string  
0004: MOV       [5], (n): 1  
0005: JRE(W)    0023, [3]               (n): 1 (n): 1 (n): 2  
0006: MOV       [7], stack[0]           (f): table.insert
-- load some functions to memory  
0007: MOV       [8], [2]                (table): ???  
0008: MOV       [9], stack[1]           (f): string.char  
0009: MOV       [10], stack[2]          (f): bit32.bxor  
000a: MOV       [11], stack[3]          (f): string.byte  
000b: MOV       [12], stack[4]          (f): string.sub  
000c: MOV       [13], [0]               (s): 4091
-- load encrypted message  
000d: MOV       [14], [6]               (n): 1  
000e: ADD       [15], [6] 1             (n): 1  
000f: LDTBL1    [12], 13 15             (s): 4091 (n): 1 (n): 2 (s): @91
-- load first char of message...  
0010: CALL      [11], 11                (n): 64
-- ...and convert to byte  
0011: MOV       [12], stack[3]          (f): string.byte  
0012: MOV       [13], stack[4]          (f): string.sub  
0013: MOV       [14], [1]               (s): 7eb1a3bb4586dba7  
0014: SUB       [15], [6] 1             (n): 1  
0015: LDCNT     [16] #[1]               (n): 8  
0016: MOD       [15], [15] [16]         (n): 0 (n): 8  
0017: ADD       [15], 1                 (n): 0
-- the part increments the current  
0018: SUB       [16], [6] 1             (n): 1
-- read index of the key and wraps  
0019: LDCNT     [17] #[1]               (n): 8
-- around if end of key is reached  
001a: MOD       [16], [16] [17]         (n): 0 (n): 8  
001b: ADD       [16], 1                 (n): 0  
001c: ADD       [16], [16] 1            (n): 1  
001d: LDTBL1    [13], 14 16             (s): 7eb1a3bb4586dba7 (n): 1 (n): 2
(s): ~b1 -- load next byte of key for xor  
001e: LDTBL3    [12], 13 #tblcnt                (n): 126  
001f: CALL      [10], 10                (n): 62
-- xor with current key byte  
0020: MOD       [10], [10] 256          (n): 62
-- mask with 0xff  
0021: LDTBL2    [9], 10 10              (n): 62 (s): >  
0022: CALL      [7], 7 #tblcnt          (n): 9
-- and convert to char... input prompt  
0023: JRL(W)    0005, [3]               (n): 1 (n): 2 (n): 2  
```

So we know how the subroutine is decrypting messages. After entering a random
string the program flow goes on. We can see that another encrypted message is
loaded with yet another decryption key. But the same subroutine is used for
decryption, so we can implement our own encryption method with `python`.

```  
0035: MOV       G['s'],                 (s):  
0036: OBJ       [8], G['s']  
0037: MOV       [9], [7]                (f): unknown  
0038: MOV       [10], (s):
df17eb31e4e81cc12fc4ef37f223d1c334cc39faf22cd915c4c321d43ec0ff2cc92ffafe22de2ffaef22c32ec7f33bf22fd6ff22dd2fd8  
0039: MOV       [11], (s): 9c43ad4aa5  
003a: CALL      [9], 9, 11  
0001: TABLE     [2]  
0002: MOV       [3], (n): 1  
0003: LDCNT     [4] #[0]                (n): 55  
0004: MOV       [5], (n): 1  
0005: JRE(W)    0023, [3]               (n): 1 (n): 1 (n): 55  
0006: MOV       [7], stack[0]           (f): table.insert  
0007: MOV       [8], [2]                (table): ???  
0008: MOV       [9], stack[1]           (f): string.char  
0009: MOV       [10], stack[2]          (f): bit32.bxor  
000a: MOV       [11], stack[3]          (f): string.byte  
000b: MOV       [12], stack[4]          (f): string.sub  
000c: MOV       [13], [0]               (s):
df17eb31e4e81cc12fc4ef37f223d1c334cc39faf22cd915c4c321d43ec0ff2cc92ffafe22de2ffaef22c32ec7f33bf22fd6ff22dd2fd8  
000d: MOV       [14], [6]               (n): 1  
000e: ADD       [15], [6] 1             (n): 1  
000f: LDTBL1    [12], 13 15             (s):
df17eb31e4e81cc12fc4ef37f223d1c334cc39faf22cd915c4c321d43ec0ff2cc92ffafe22de2ffaef22c32ec7f33bf22fd6ff22dd2fd8
(n): 1 (n): 2 (s): df17  
0010: CALL      [11], 11                (n): 223  
```

```python  
flag =
bytearray.fromhex("df17eb31e4e81cc12fc4ef37f223d1c334cc39faf22cd915c4c321d43ec0ff2cc92ffafe22de2ffaef22c32ec7f33bf22fd6ff22dd2fd8")  
key = bytearray.fromhex("9c43ad4aa5")

for i,c in enumerate(flag):  
   x.append(chr(c^key[i%len(key)]))  
```

It's as easy as this, after running the script we get our flag. And for good
measure, lets enter the correct flag:

```  
$ lua zermatt.lua  
_____             _     ___ _____ ____  
|   __|___ ___ ___| |___|   |_   _|  __|  
|  |  | . | . | . | | -_| -<  | | |  __|  
|_____|___|___|_  |_|___|___| |_| |_|  
             |___|       ZerMatt - misc  
> CTF{At_least_it_was_not_a_bytecode_base_sandbox_escape}  
WIN  
```

The deobfuscated state of the script with debug code can be found
[`here`](https://github.com/D13David/ctf-
writeups/blob/main/googlectf23/rev/zermatt/zermatt1.lua).

Flag `CTF{At_least_it_was_not_a_bytecode_base_sandbox_escape}`

Original writeup (https://github.com/D13David/ctf-
writeups/blob/main/googlectf23/rev/zermatt/README.md).