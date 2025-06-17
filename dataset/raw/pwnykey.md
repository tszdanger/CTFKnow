# pwnykey (rev)  
Writeup by: [xlr8or](https://ctftime.org/team/235001)

Full disclosure: I haven't had time to solve this during the contest and I was
very tired, so I solved it the next day. I hope it is not a problem to post a
writeup about a challenge I didn't solve during the contest.

## Architecture  
First let's focus on the challenge architecture. We got a compressed file with
all kinds of files and folders.  
* `static/` contains frontend code of the challenge website  
* `Dockerfile` docker file to build a contain from, will run the whole challenge infrastructure  
* `.devicescript/` contains binary for devicescript simulation, this won't concern us  
* `flag.txt` yeah the flag  
* `app.py` backend code for the challenge website  
* `package.json` npm package config file - for installing `devicescript` CLI  
* `keychecker.devs` compiled devicescript bytecode

The dataflow is as follows:  
1. We enter the key on the website, which will make  POST request to `/check`  
2. The backend will store the key we have entered and invoke the checker, the devicescript binary  
3. The devicescript binary will make a GET request to `/check` to retrieve the key we have just entered  
4. The deviscescript binary will perform the checks and let the backend know about the result  
5. The backend sends us the either the flag, or a failure message.

It is clear that most of the architecture here is just noise and the
devicescript blob is where the main work needs to be done.

## Devicescript  
Devicescript is made by Microsoft to be a typescript like language for
embedded development. The source code can be compiled to a custom bytecode
format, which their custom runtime written in C can execute.

After learning more about the [runtime
implementation](https://microsoft.github.io/devicescript/language/runtime), I
have noticed that the CLI can be used to get a disassembly. So I ran the
disassembler (`node ./node_modules/@devicescript/cli/devicescript disasm -d
keychecker.devs`) and got the output, however it is not as good as advertised
on the linked documentation page.  
```  
proc main_F0(): @1120  
 locals: loc0,loc1,loc2  
  0:     CALL prototype_F1{F1}() // 270102  
???oops: Op-decode: can't find jump target 10; 0c // 0df90007  
  7:     RETURN undefined // 2e0c  
  9:     JMP 39 // 0d1e  
???oops: Op-decode: stack underflow; 4c // 4c  
???oops: Op-decode: stack underflow; 250003 // 250003  
???oops: Op-decode: can't find jump target 22; 0c // 0df90007  
 19:     RETURN undefined // 2e0c  
???oops: Op-decode: can't find jump target 51; 0c // 0d1e  
 23:     CALL ???oops op126(62, ret_val()) // 7ece2c04  
???oops: Op-decode: can't find jump target 34; 0c // 0df90007  
 31:     RETURN undefined // 2e0c  
???oops: Op-decode: can't find jump target 72; 0c // 0d27  
???oops: Op-decode: stack underflow; 02 // 02  
???oops: Op-decode: stack underflow; 253303 // 253303  
???oops: Op-decode: can't find jump target 46; 0c // 0df90007  
 43:     RETURN undefined // 2e0c  
 45:     JMP 89 // 0d2c  
???oops: Op-decode: stack underflow; 1b34 // 1b34  
???oops: Op-decode: stack underflow; 02 // 02  
???oops: Op-decode: can't find jump target 57; 0c // 0df90007  
 54:     RETURN undefined // 2e0c  
```

These are the first few lines of the disassembly for the main function, which
is the entry of devicescript binaries. There are a lot of decoding problems
concerning stack underflows and missing jump targets. I won't put the full
disassembly here (~4k lines), but the rest of it is full of these decoding
problems. At the end we can find some useful information as well, which is
like the *data section* of the binary:  
```  
Strings ASCII:  
  0: "start!"  
  1: "fetch"  
  2: "method"  
  3: "GET"  
  4: "headers"  
  5: "Headers"  
  6: "body"  
  7: "tcp"  
  8: "startsWith"  
  9: "https://"  
 10: "tls"  
 11: "http://"  
 12: "invalid url: {0}"  
 13: "/"  
 14: "includes"  
 15: "@"  
 16: "credentials in URL not supported: {0}"  
 17: ":"  
 18: "invalid port in url: {0}"  
 19: "body has to be string or buffer; got {0}"  
 20: "has"  
 21: "user-agent"  
 22: "DeviceScript fetch()"  
 23: "accept"  
 24: "*/*"  
 25: "host"  
 26: "connection"  
 27: "content-length"  
 28: "{0} {1} HTTP/1.1\r\n{2}\r\n"  
 29: "serialize"  
 30: "connect"  
 31: "Socket"  
 32: "buffers"  
 33: "emitter"  
 34: "_connect"  
 35: "port"  
 36: "proto"  
 37: "req: {0}"  
 38: "send"  
 39: "Response"  
 40: "socket"  
 41: "readLine"  
 42: "HTTP/1.1 "  
 43: "status"  
 44: " "  
 45: "statusText"  
 46: "ok"  
 47: "HTTP {0}: {1}"  
 48: "trim"  
 49: "append"  
 50: "{0}"  
 51: "http://localhost/check"  
 52: "text"  
 53: "fetched key: {0}"  
 54: "Invalid key"  
 55: "split"  
 56: "-"  
 57: "some"  
 58: "key format ok"  
 59: "passed check1"  
 60: "concat"  
 61: "reduce"  
 62: "passed check2"  
 63: "nextInt"  
 64: "passed check3"  
 65: "success!"  
 66: "0123456789ABCDFGHJKLMNPQRSTUWXYZ"  
 67: "socket {0}: {1}"  
 68: "check"  
 69: "old socket used"  
 70: "recv"  
 71: "lastError"  
 72: "closed"  
 73: "send error {0}"  
 74: "finish"  
 75: "emit"  
 76: "socket {0} {1} {2}"  
 77: "unknown event {0}"  
 78: "terminated"  
 79: "{0}://{1}:{2}"  
 80: "connecting to {0}"  
 81: "can't connect: {0}"  
 82: "timeout"  
 83: "Timeout"  
 84: ", "  
 85: "\r\n"  
 86: "{0}: {1}"  
 87: "isSpace"  
 88: "splitMatch"  
 89: "Emitter"  
 90: "handlers"  
 91: "handlerWrapper"  
 92: "_buffer"  
 93: "Assertion failed: "  
 94: "noop"  
 95: "start!"

Strings UTF8:  
  0: " \t\n\r\u000b\f" (62 bytes 25 codepoints)

Strings buffer:

Doubles:  
  0: 12534912000  
  1: 4294967295  
  2: 2897974129

```

These will be incredibly useful later, for now it is good that we notice some
of the printed output when running the program inside the binary as well. We
can also infer that there will be 3 checks, and this is where we know from
that a request to `/check` will be made.  
The binary can be run with `node ./node_modules/@devicescript/cli/devicescript
run -t keychecker.devs`.

Here I got stuck for hours, I was trying to figure out how to make
decompilation work better, I was trying to look into dynamic analysis, I
looked into the *devtools* of the CLI. I really wasn't sure if I was missing
something or if the solution was (again) to make a disassembler. I wasted a
lot of time trying to avoid the latter, however in the end I did decide to go
with it, since I saw no other alternative.

## Why is the disassembler failing  
Let's start by looking at the file that's responsible for performing the
disassembly.  
```js  
#
https://github.com/microsoft/devicescript/blob/ee4872a32f89e47a02cb2d05b3aab2000ca0f56b/compiler/src/disassemble.ts#L280C4-L291C6  
for (const stmt of stmts) {  
       try {  
           if (opJumps(stmt.opcode)) {  
               const trg = byPc[stmt.intArg]  
               if (!trg) error(`can't find jump target ${stmt.intArg}`)  
               stmt.jmpTrg = trg  
           }  
       } catch (e) {  
           if (throwOnError) throw e  
           else stmt.error = e.message  
       }  
   }  
```

Here is where the jump target error originates from. This happens when `byPc`
doesn't contain an entry for the jump target. Let's look at what `byPc` is  
```js  
#
https://github.com/microsoft/devicescript/blob/ee4872a32f89e47a02cb2d05b3aab2000ca0f56b/compiler/src/disassemble.ts#L245C5-L278C6  
while (pc < bend) {  
       try {  
           stmtStart = pc  
           jmpoff = NaN  
           const op = decodeOp()  
           const stmt = new OpStmt(op.opcode)  
           stmt.pc = stmtStart  
           stmt.pcEnd = pc  
           stmt.intArg = op.intArg  
           stmt.args = op.args  
           if (opJumps(stmt.opcode)) {  
               const trg = jmpoff + stmt.intArg  
               if (!(0 <= trg && trg < bytecode.length)) {  
                   error(`invalid jmp target: ${jmpoff} + ${stmt.intArg}`)  
               }  
               stmt.intArg = trg  
           }

           stmt.index = stmts.length  
           stmts.push(stmt)  
           byPc[stmt.pc] = stmt  
       } catch (e) {  
           if (throwOnError) {  
               throw e  
           } else {  
               const stmt = new OpStmt(Op.STMT0_DEBUGGER)  
               stmt.error = e.message  
               if (stmtStart == pc) pc++  
               stmt.pc = stmtStart  
               stmt.pcEnd = pc  
               stmts.push(stmt)  
           }  
       }  
   }  
```  
Here's where `byPc` gets updated. Basically whenever the decoder creates a
statement it creates an entry for statement's pc in the array. And here we can
already see the problem. The decoder works sequentially from the start of the
instruction list to the end of it. If a jump happens to go in the middle of an
instruction, the disassembler will complain, that the jump target can't be
found.  
However during execution this behavior is fine, as long as the instruction we
decode after taking the jump is valid. Let's take an example to illustrate
this point (the bytecode below is fictional):  
```  
0x00 0x01 0x02 ; call a function  
0x01 0x04          ; jump 4 bytes  
0x00 0x01 0x02 ; call a function  
0x03 0x04          ; print 4  
0x07                   ; exit  
...  
```  
Here the jump instruction would go to byte 0x04, but the decoder already has
0x04 as part of another instruction (with code 0x03). However it can be the
case that after jumping to 0x04, we would get a valid instruction still, let's
say that (0x04 0x07) means push 7 on the stack.  
In essence the jump skips some bytes, which will never be used (0x00 0x01 0x02
0x03 here), and the decoder assumes that there are no such wasted bytes, that
after one instruction another instruction follows, which is not the case here.

So now that we have identified the shortcoming of the builtin disassembler it
is time to build ours.

## Making the disassembler  
The [bytecode example
documentation](https://microsoft.github.io/devicescript/language/runtime#bytecode-
example) was helpful in getting started with the disassembler. We see that
each operation is assigned some 8-bit number, some operations take extra
arguments, we have immediates, we have *references* for functions, doubles, we
have some builtin strings and objects

### The bytecode  
A [detailed description of the
bytecode](https://github.com/microsoft/devicescript/blob/main/bytecode/bytecode.md)
helps with this task. This file defines all the bytecodes, some binary format
constants, such as the magic byte, and some builtin string tables. Here we can
check what operation an opcode belongs to, and we also get information about
how many arguments an operation takes.

Important to note, that there is a stack for this VM as well. Some operations
are *expressions* that put results on top of stack, and *statements* store the
result in a temporary location, which can be accessed by a separate
instruction. *expressions* have a return type in the document, but
*statements* do not.

When taking arguments operations can use the stack and immediates as well.
Parameters that being with `*` are immedates, others are taken from the stack.
The rightmost argument is taken from the top of the stack, while the leftmost
is at the lowest postion compared to the other arguments.

While this covers most of the operations there are come opcodes that are not
listed. These were all above `0x90`, and although the documentation doesn't
mention them, there's a mention of it in the bytecode example, with
`0x92-0x90` meaning a constant of 2.

Providing immediates is also interesting and worth its own section.  
### Immediates  
Immediates are encoded to be variable length integer values.

```js  
#
https://github.com/microsoft/devicescript/blob/ee4872a32f89e47a02cb2d05b3aab2000ca0f56b/compiler/src/disassemble.ts#L331C5-L346C6  
function decodeInt() {  
       const v = getbyte()  
       if (v < BinFmt.FIRST_MULTIBYTE_INT) return v

       let r = 0  
       const n = !!(v & 4)  
       const len = (v & 3) + 1

       for (let i = 0; i < len; ++i) {  
           const v = getbyte()  
           r = r << 8  
           r |= v  
       }

       return n ? -r : r  
   }  
```

We get the first byte of the immediate and return it if it isn't high enough
(0xf8 according to the bytecode docs). Otherwise the first byte is treated as
an information byte that tells us the sign of the result, and the number of
bytes that follow. The rest of the integer is decoded in a big-endian manner
(MSB first), and we return the result with the proper sign.

### Handling jumps  
To address the problem of the official disassembler, whenever there's an
unconditional jump with a positive offset, the decoder will *take the jump* as
a runtime would to avoid missing jump targets. This means that the
disassembler will skip some bytes, but that is fine, since thankfully nothing
returns to them later (that would have been an interesting twist to the
challenge).

### Putting it all together  
The disassembler will act on functions, and their bounds need to be manually
specified directly in the disassembler source code. The bounds can be
retrieved from the output of the official disassemler.

Some lookup tables for strings, objects and doubles are also hardcoded into
the disassembler, these are taken from the official disassembler output as
well.

Finally I manually added an entry for each encountered op code.

I present you the disassembler:  
```python  
fp = open('./pwnykey/keychecker.devs', 'rb')  
content = fp.read()  
fp.close()

ptr = 5164  
num_split = 0xf8  
seek_end = 5292

opf =
b"\x7f\x60\x11\x12\x13\x14\x15\x16\x17\x18\x19\x12\x51\x70\x31\x42\x60\x31\x31\x14\x40\x20\x20\x41\x02\x13\x21\x21\x21\x60\x60\x10\x11\x11\x60\x60\x60\x60\x60\x60\x60\x60\x10\x03\x00\x41\x40\x41\x40\x40\x41\x40\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x41\x32\x21\x20\x41\x10\x30\x12\x30\x70\x10\x10\x51\x51\x71\x10\x41\x42\x40\x42\x42\x11\x60"

builtinmap = {  
   0: 'Math',  
   # -- SNIP --  
   43: 'GPIO_prototype',  
}  
dsmap = {  
   0: '',  
   1: 'MInfinity',  
   2: 'DeviceScript',  
   # -- SNIP --  
   215: 'encrypt',  
   216: 'decrypt',  
   217: 'digest',  
}

strmap = {  
  0: "start!",  
  1: "fetch",  
  # -- SNIP --  
 95: "start!",  
}

def get_num(cur):  
   if content[cur] < num_split: return content[cur], 0  
   is_neg = (content[cur] & 4 != 0)  
   loop_cnt = (content[cur] & 3) + 1  
   result = 0  
   for i in range(loop_cnt):  
       result <<= 8  
       result |= content[cur + i + 1]

   return result if not is_neg else -result, loop_cnt

def op_takes_num(opc):  
   return opf[opc] & 0x20 != 0

def num_args(opc):  
   return opf[opc] & 0x0f

while ptr < seek_end:  
   print(hex(ptr), end=' - ')  
   if content[ptr] == 0x27:  
       print(f'func_ref {content[ptr + 1]}')  
       ptr += 2  
   elif content[ptr] == 0x02:  
       print('func(argc=0)')  
       ptr += 1  
   elif content[ptr] == 0x03:  
       print('func(argc=1)')  
       ptr += 1  
   elif content[ptr] == 0x04:  
       print('func(argc=2)')  
       ptr += 1  
   elif content[ptr] == 0x0d:  
       jnum, ln = get_num(ptr + 1)  
       print(f'jump @+{jnum}')  
       ptr += jnum if jnum > 0 else 2 + ln  
   elif content[ptr] == 0x0e:  
       jnum, ln = get_num(ptr + 1)  
       print(f'jump if (not TOS) @+{jnum}')  
       ptr += 2 + ln  
   elif content[ptr] == 0x1e:  
       idx, ln = get_num(ptr + 1)  
       print(f'ds[{idx}] ("{dsmap[idx]}")')  
       ptr += 2 + ln  
   elif content[ptr] == 0x25:  
       idx, ln = get_num(ptr + 1)  
       print(f'ascii_string[{idx}] ("{strmap[idx]}")')  
       ptr += 2 + ln  
   elif content[ptr] >= 0x90:  
       print(f'TOS = {content[ptr] - 0x90}')  
       ptr += 1  
   elif content[ptr] >= len(opf) or content[ptr] == 0x00:  
       print('NOP')  
       ptr += 1  
   elif content[ptr] == 0x2c:  
       print('ret_val()')  
       ptr += 1  
   elif content[ptr] == 0x1b:  
       idx, ln = get_num(ptr + 1)  
       print(f'obj[ascii_string[{idx}]] -- obj is TOS; ("{strmap[idx]}")')  
       ptr += 2 + ln  
   elif content[ptr] == 0x12:  
       idx, ln = get_num(ptr + 1)  
       print(f'global[{idx}] = TOS')  
       ptr += 2 + ln  
   elif content[ptr] == 0x16:  
       idx, ln = get_num(ptr + 1)  
       print(f'TOS = global[{idx}]')  
       ptr += 2 + ln  
   elif content[ptr] == 0x1a:  
       idx, ln = get_num(ptr + 1)  
       print(f'obj[ds[{idx}]] -- obj is TOS ("{dsmap[idx]}")')  
       ptr += 2 + ln  
   elif content[ptr] == 0x47:  
       print('ST-1 != ST-2')  
       ptr += 1  
   elif content[ptr] == 0x01:  
       idx, ln = get_num(ptr + 1)  
       print(f'TOS = builtin_objs[{idx}] ("{builtinmap[idx]}")')  
       ptr += 2 + ln  
   elif content[ptr] == 0x58:  
       print('TOS = new(TOS)')  
       ptr += 1  
   elif content[ptr] == 0x54:  
       print('throw(TOS)')  
       ptr += 1  
   elif content[ptr] == 0x4b:  
       idx, ln = get_num(ptr + 1)  
       print(f'TOS = make_closure(func_idx={idx})')  
       ptr += 2 + ln  
   elif content[ptr] == 0x11:  
       idx, ln = get_num(ptr + 1)  
       print(f'local[{idx}] = TOS')  
       ptr += 2 + ln  
   elif content[ptr] == 0x15:  
       idx, ln = get_num(ptr + 1)  
       print(f'TOS = local[{idx}]')  
       ptr += 2 + ln  
   elif content[ptr] == 0x18:  
       print('TOS = ST-2[ST-1]')  
       ptr += 1  
   elif content[ptr] == 0x20:  
       print('new Array(ST-1) -- doesnt modify stack')  
       ptr += 1  
   elif content[ptr] == 0x19:  
       print('ST-3[ST-2] = ST-1')  
       ptr += 1  
   elif content[ptr] == 0x28:  
       literal, ln = get_num(ptr + 1)  
       print(f'TOS = {literal}')  
       ptr += 2 + ln  
   elif content[ptr] == 0x38:  
       print(f'TOS = (not ST-1)')  
       ptr += 1  
   elif content[ptr] == 0x29:  
       idx, ln = get_num(ptr + 1)  
       print(f'TOS = doubles[{idx}]')  
       ptr += 2 + ln  
   elif content[ptr] == 0x46:  
       print(f'TOS = ST-2 < ST-1')  
       ptr += 1  
   elif content[ptr] == 0x3a:  
       print('TOS = ST-1 + ST-2')  
       ptr += 1  
   elif content[ptr] == 60:  
       print('TOS = ST-1 * ST-2')  
       ptr += 1  
   elif content[ptr] == 66:  
       print('TOS = ST-2 >> ST-1')  
       ptr += 1  
   elif content[ptr] == 62:  
       print('TOS = ST-2 & ST-1')  
       ptr += 1  
   elif content[ptr] == 64:  
       print('TOS = ST-2 ^ ST-1')  
       ptr += 1  
   elif content[ptr] == 65:  
       print('TOS = ST-2 << ST-1')  
       ptr += 1  
   elif content[ptr] == 0xc:  
       print('return ST-1')  
       ptr += 1  
   elif content[ptr] == 36:  
       idx, ln = get_num(ptr + 1)  
       print(f'TOS = ds[{idx}] ("{dsmap[idx]}")')  
       ptr += 2 + ln  
   else:  
       print(f'unknown byte code {content[ptr]} @ {ptr}')  
       break;  
```

Note: I have omitted most mapping entries for clarity, however they can be
easily reconstructed from the official disassembler output, and the bytecode
docs.  
The code could be nicer by utilizing some information about the opcodes and
re-using code, but it is good enough for now.

The disassembler further help by performing lookups for strings, builtin
strings and builtin objects.

## Decompiling  
The disassembly of `main` is already quite nice, just below 400 lines, with
friendly js-like instructions. However I wanted to gain a better understanding
of the binary, so I have converted the disassembly (manually) to a js-like
format.

I won't put the disassembled results here for clarity, but they can be
generated using the script above and modifying the bounds, so that the desired
function is disassembled.

Besides `main` I have converted (manually) all other functions that were
referenced (except for `fetch` and the very first function that all
devicescript binaries call, since their function is either clear or not
important to the challenge -- although it would have been funny if `fetch` was
overridden to modify the result hehe).  
So here's the (manually) decompiled version of the devicescript binary:  
```js  
init_func()  
print(format("start!"), 62)  
const resp = fetch("http://localhost/check")  
const result = resp.text().trim() // global[4]  
print(format("fetched key: {0}", result), 62)  
if (result.length != 29) throw new Error("Invalid key")

const keyParts = result.split("-"); // global[5]  
if (keyParts.length != 5) throw new Error("Invalid key")

function func7(part) {  
   retrun part.length != 5;  
}

function func8(arg) {  
   return arg.split("").some(func14);  
}

function func9(arg) {  
   return arg.split("").map(func15);  
}

function func10(a, b) {  
   let res = [];  
   for (let i = 0; i < a.length; ++i) res.push(a[i]);  
   for (let i = 0; i < b.length; ++i) res.push(b[i]);  
   return res;  
}

function func11(a, b) {  
   return a + b;  
}

function func12(a, b) {  
   return a * b;  
}

function func14(x) {  
   return "0123456789ABCDFGHJKLMNPQRSTUWXYZ".includes(x);  
}

function func15(x) {  
   return "0123456789ABCDFGHJKLMNPQRSTUWXYZ".indexOf(x);  
}

const res = keyParts.some(func7);  
if (res) throw new Error("Invalid key")

const res2 = keyParts.some(func8);  
if (res2) throw new Error("Invalid key")

print(format("key format ok"), 62)

let vres1 = keyParts.map(func9); // local[0]  
const vp0 = vres[0]; // global[6]  
const vp1 = vres[1]; // global[7]  
const vp2 = vres[2]; // global[8]  
const vp3 = vres[3]; // global[9]  
const vp4 = vres[4]; // global[10]

vres1 = format("{0}", vp0) // local[0]  
const varr1 = new Array(5); // local[1]  
varr1[0] = 30;  
varr1[1] = 10;  
varr1[2] = 21;  
varr1[3] = 29;  
varr1[4] = 10;

if (vres != format("{0}", varr1)) throw new Error("Invalid key")

print(format("passed check1"), 62)

let vres2 = func10(vp1, vp2); // global[11]  
if (vres2.reduce(func11, 0) != 134) throw new Error("Invalid key")  
if (vres2.recude(func12, 1) != 12534912000) throw new Error("Invalid key") //
constant from doubles[0]

print(format("passed check2"), 62)

let vv3 = vp3; // global[12]  
let vv3_2 = 1337; // global[13]  
const d1 = 0; // TODO constant from doubles[1]

function func13() {  
   let x = vv3.pop();  
   x = ((x >> 2) & d1) ^ x;  
   x = ((x << 1) & d1) ^ x;  
   x = (((vv3[0] << 4) ^ vv3[0]) & d1) ^ x  
   vv3_2 = (13371337 + vv3_2) & d1

   vv3.unshift(x);

   return x + vv3_2;  
}

for (let i = 0; i < 420; ++i) f3 = func13();

const varr3 = new Array(3); // local[0]  
varr3[0] = func13();  
varr3[1] = func13();  
varr3[2] = func13();

const vr3 = format("{0}", varr3); // local[0]

const varr3_2 = new Array(3); // local[1]  
varr3_2[0] = doubles[2];  
varr3_2[1] = -549922559;  
varr3_2[2] = -387684011;

const vr3_2 = format("{0}", varr3_2);  
if (vr3 != vr3_2) throw new Error("Invalid key")

print(format("passed check3"), 62)  
print(format("success!"), 62)  
return 0;  
```

The checks can be clearly seen from this version. Some comments are placed to
indicate where some variable is placed in `locals` or `globals` array in the
VM.

Based on this we can begin the journey to construct a working pwnyos key.

## Forging a key  
As can be seen from the above code, the key should be 29 chars long, have 5
parts of length 5 separated by `-`. Each part can contain the 10 digits and
uppercase ascii letters, expect captial O, capital I, capital E and capital V.

After this the key format is deemed valid, and the checks are executed. There
are 3 checks in total, and the last group of 5 chars is never checked.

Each character is converted to its index in the array of valid characters for
future processing.

### Check 1  
This check will ensure that the first group of 5 chars is correct. It will do
so by comparing the first 5 entries against a hard coded value. Since these
values are the indices of the characters in the valid character array,
reversing the operation to get the actual characters is trivial.  
```python  
valid_chars = '0123456789ABCDFGHJKLMNPQRSTUWXYZ'

part1 = [None] * 5  
part1[0] = valid_chars[30];  
part1[1] = valid_chars[10];  
part1[2] = valid_chars[21];  
part1[3] = valid_chars[29];  
part1[4] = valid_chars[10];

print(''.join(part1))  
```

### Check 2  
The complexity is ramping up. First we merge the index array for the second
and third part of the key, so that it becomes an array of size 10, still
containing indices of the chars in the valid char array.  
The sum of all items in this newly generated array should be 134 and their
product should be 12534912000.  
We can ~~brute force~~ SAT solve this:  
```python  
from z3 import *  
def get_part2():  
   result = [ BitVec("k%s" % (i), 32) for i in range(10) ]  
   s = Solver()

   sm = 0  
   prod = 1  
   for tok in result:  
       s.add(tok >= 1)  
       s.add(tok < len(valid_chars))  
       sm = sm + tok  
       prod = prod * tok

   s.add(sm == 134)  
   s.add(prod == 12534912000)

   print(s.check())  
   m = s.model()

   psat = []  
   for i in range(len(result)):  
       psat.append(int(str(m.evaluate(result[i]))))

   print(psat)

   sm = 0  
   prod = 1  
   for x in psat:  
       sm += x  
       prod *= x

   print(sm, prod)

   part23 = ""  
   for x in psat:  
       part23 += valid_chars[x]

   print(part23[:5] + '-' + part23[5:])  
```

Maybe interesting to note here is that if I set the bit vector size to 8 bits
(since the individual values shouldn't exceed this) the solver returns invalid
results, however with 32-bit we get valid results.

### Check 3  
(during this I ran out of contest time and fell asleep)

This check is the most complicated. A function is called which does
computations on the 4th group of 5 chars (still the index array) 420 times.
Then the next 3 results of the function are checked against some hardcoded
values.

I have tried SAT solving this, but I didn't manage to make it work I still
need to get better at these types of challenges.  
So let's ~~SAT solve~~ brute force this problem, as the search space is *not
that bad*.

```cpp  
#include <cstdio>  
#include <deque>

using namespace std;

void print_array(int* arr, size_t length) {  
   for (int i = 0; i < length; ++i) {  
       printf("%d, ", arr[i]);  
   }  
   printf("\n");  
}

int vv3_2 = 1337;  
int d1 = 4294967295;  
int d2 = 2897974129;

long long func13(deque<int>& vv3) {  
   int x = vv3.back(); vv3.pop_back();  
   x = ((x >> 2) & d1) ^ x;  
   x = ((x << 1) & d1) ^ x;  
   x = (((vv3[0] << 4) ^ vv3[0]) & d1) ^ x;  
   vv3_2 = (13371337 + vv3_2) & d1;

   vv3.push_front(x);

   return x + vv3_2;  
}

int check(int* arr) {  
   deque<int> copy {arr[0], arr[1], arr[2], arr[3], arr[4]};  
   vv3_2 = 1337;  
   for (int i = 0; i < 420; ++i) func13(copy);  
   int a1 = func13(copy);  
   int a2 = func13(copy);  
   int a3 = func13(copy);

   return (a1 == d2 && a2 == -549922559 && a3 == -387684011) ? 1 : 0;  
}

int dfs(int cur, int* arr) {  
   if (cur == 5) {  
       int res = check(arr);  
       if (res == 1) {  
           print_array(arr, 5);  
       }  
       return res;  
   }

   for (int i = 0; i < 32; ++i) {  
       if (cur == 0) printf("at %d\n", i);  
       arr[cur] = i;  
       if (dfs(cur + 1, arr) == 1) return 1;  
   }

   return 0;  
}

int main() {  
   int arr[5] = {0, 0, 0, 0, 0};  
   dfs(0, &arr[0]);  
   return 0;  
}  
```

I have decided to write this in c++, because I didn't trust python with
keeping the numbers to be signed 32-bit values. After running this for a bit,
we do get a result that satisfies all conditions.

```python  
  valid_chars = '0123456789ABCDFGHJKLMNPQRSTUWXYZ'  
   k = [14, 11, 22, 2, 27]  
   part4 = ''  
   for x in k:  
       part4 += valid_chars[x]  
   print(part4)  
```

## The end  
So the final activation key to pwnyos is: YANXA-CC52K-5TG8Z-FBP2U-12345 (you
can vary the last 5 chars if someone activated pwnyos already with this one ;)
)  
And the flag I got after the contest has ended is:
uiuctf{abbe62185750af9c2e19e2f2}