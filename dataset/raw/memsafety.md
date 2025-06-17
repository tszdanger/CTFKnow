# Overview

A server written in rust, which creates and runs Services (a Service there is
a trait, a traits are similar to interfaces in other languages).  
There are two Services, one is implemented in `user_1` module which is
predefined and the other one (`user_0`) is supposed to be implemented by the
user.

A Python code wraps it all - receives the code of `user_0`, build the program
and executes it.

Pretty simple, but how's it related to the flag? It is actually placed as a
constant string in the predefined module:

```rust  
#![no_std]  
use proc_sandbox::sandbox;

#[sandbox]  
pub mod user {  
   static FLAG: &'static str = "CTF{fake flag}";  
   use prelude::{mem::ManuallyDrop, Service, Box, String};  
   pub struct State(ManuallyDrop<String>);  
   impl State {  
       pub fn new() -> Box<dyn Service> {  
           Box::new(State(ManuallyDrop::new(String::from(FLAG))))  
       }  
   }  
   impl Service for State {  
      fn handle(&mut self, _: &str) {}  
   }  
}  
```

I'm not very experienced in rust but I've seen some code and the use of
[ManuallyDrop](https://doc.rust-lang.org/std/mem/struct.ManuallyDrop.html) was
not familliar to me. As it wraps the flag, it is worth mentioning that the
object is a wrapper can be used to inhibit compiler from automatically calling
the destructor of the wrapped struct.  
So it means the flag stays in memory? Interesting

And there is a sandbox. Actually in my point of view there were 3 "layers" of
limitations, and the sandbox is one of them:

### Python validation  
The user's input is being validated before the program is run (but after
compiling). That's the function:

```python  
def check_user_input():  
   socket_print("Validating user input before compiling...")  
   result =
subprocess.run("/home/user/rustup/toolchains/nightly-2020-10-08-x86_64-unknown-
linux-gnu/bin/rustc user-0/src/lib.rs -Zast-json=yes",  
                           cwd="/home/user/sources", shell=True, timeout=150, capture_output=True)  
   try:  
       ast = json.loads(result.stdout)  
       if len(ast["module"]["items"]) != 5:  
           socket_print("Module escaping detected, aborting.")  
           sys.exit(1)

   except json.JSONDecodeError:  
       socket_print(  
           "Something went wrong during validation -- is your input malformed?")  
       sys.exit(1)

```

It tries to check module escaping using a feature of the rust compiler
(exporting the AST).

**What actually caught my mind is the old version of the toolchain - should I
exploit an old bug?**

### The sandbox

The sandbox is implemented as a [Procedural Macro](https://doc.rust-
lang.org/reference/procedural-macros.html) (more specific - attribute macro),
which allow running code that consumes and produces rust syntax.

The `Sandbox` goes over the user-modules AST and checks for blocked
operations:  
* The `unsafe` expression.  
* Linking to external symbol.  
* `extern` declaration.  
* Blocked idents (idents are keywords or illegal phrases): `env`, `file`, `include`, `include_bytes`,`include_str`, `option_env`, `std`

### Overriding `prelude`

In rust, [prelude](https://doc.rust-lang.org/std/prelude/index.html) is a list
of things that rust automatically imports to every program, particularly for
convenience.

It is possible to define your own prelude and that what happens in this
challenge, so it goes hand to hand with the sandbox.

The `Service` trait is also defined in the same file.

```rust  
pub use std::io::Read;  
pub use std::io::Result as IoResult;  
pub use std::vec::Vec;  
pub use std::println as log;  
pub use std::string::String;  
pub use std::str;  
pub use std::mem;  
pub use std::boxed::Box;

pub trait Service {  
   fn handle(&mut self, query: &str);  
}  
```

# My (unintended) way to the solution

There were some "hints" that led me to think I should get the flag by
exploiting a bug that existed in that old version of rust and it should likely
be related to memory issues - `DropManually` that keeps the flag in memory,
the old toolchain and the name of the challenge.

But I had another idea.

As mentioned before, the sandbox is implemented as a Procedural Macro, which
made me think - In what order the build-time code is run?  **What if I define
a macro inside the module and call it later?**

The answer is the macro defined inside the module actually processed later and
as a result can bypass the sandbox limitations :)

Now I need to get the flag and since I know the absolute path of the project
in the server (the path exists in their Python code), the easiest way for me
was just reading the source code file from the disk.  
In order to read from disk you need to use `std` library, and although the
sandbox is not an issue anymore, the library cannot be imported because of the
prelude overriding.

But as a result of defeating the sandbox, the predule is not an issue anymore
- I can use `extern crate`.  
`extern crate` declaration specifies a dependency on an external crate, [and
is likely no longer needed in most cases now](https://doc.rust-
lang.org/edition-guide/rust-2018/module-system/path-clarity.html) as `use` is
more convenient.

[It is possible to use `extern crate` to add symbols to the `extern
prelude`](https://doc.rust-lang.org/reference/names/preludes.html#extern-
prelude)

Now that no problems left to be solved, the payload:  
```rust  
   use prelude::{Service, Box, String, log};

   macro_rules! get_the_flag {  
       ($e:expr) => {  
           extern crate std;  
           use std::fs;  
           let all = fs::read_to_string("/home/user/sources/user-1/src/lib.rs").expect("whatever");  
           log!("{}",all);  
       };  
   }

   pub struct State;  
   impl State {  
       pub fn new() -> Box<dyn Service> {  
           get_the_flag!("");  
           Box::new(Self)  
       }  
   }

   impl Service for State {  
      fn handle(&mut self, _: &str) {  
      }  
   }  
```

And the flag - `CTF{s4ndb0x1n9_s0urc3_1s_h4rd_ev3n_1n_rus7}`

In fact it turned out the intended solution is actually as "hinted" , as seen
in [the original writeup](https://github.com/google/google-
ctf/tree/master/2021/quals/pwn-memsafety)  

Original writeup (https://github.com/OmerYe/ctf-
writeups/blob/master/2021/google/memsafety/writeup.md).Please, write just a link to original writeup here. (What? Everybody just
ignores that "warning")

Original writeup (http://r3ka.eu/2018/03/n1ctf-2018-memsafety-writeup/).