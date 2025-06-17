# game-graphics-debugging

*this is a clone. check out the original! [https://github.com/Om3rR3ich/CTF-Writeups/blob/main/WolvCTF%202024/game_graphics_debugging.md](https://github.com/Om3rR3ich/CTF-Writeups/blob/main/WolvCTF%202024/game_graphics_debugging.md)*

solver: [5h4d0w ](https://github.com/Om3rR3ich)  
writeup-writer: [5h4d0w](https://github.com/Om3rR3ich)  

## Challenge Description

**Author:** ravbug  
**Description**: I put a flag in this game, but I can't see it! Can you find
it for me?

![chall_description](https://github.com/Om3rR3ich/CTF-
Writeups/assets/88339137/8bfd59fa-4281-4299-b451-1da7cb87fb15)

As per usual - you're given a binary (in this case, you can choose your
favorite architecture), and you're supposed to find the hidden flag.  
Unlike many reversing challenges, there's not a clear path to the goal (e.g.
pass the authentication system).

## Sometimes Broken Things Deserve to Be Repaired  
Before diving into the binary, I decided to run it to get a feel for what it
does:

![error_message](https://github.com/Om3rR3ich/CTF-
Writeups/assets/88339137/12af9638-9827-41a1-9239-2ecb289ef780)

Well, it looks like some setup needs to be done to even begin reversing this.

The application fails to find an expected symbol (`vkCmdPipelineBarrier2`), so
it crashes.  
A quick google search yields that this is a function in Vulkan - a cross-
platform 3D graphics API (hence the support of multiple archicterus in this
challenge).  
Nevertheless, if you've solved `Missing Resources`, you know how these error
messages can be misleading. The problem might be way deeper.  
To make sure, I loaded the app into IDA and debugged the execution flow.  
To avoid crashing (IDA defaults to running the given executable without
suspending at any point), I enabled `Suspend on library load/unload` (in
Debugger->Debugger options).  
In addition, I recommend enabling `Suspend on entry point`, to easily check
whether the entry point is ever reached.

![dlls_loaded](https://github.com/Om3rR3ich/CTF-
Writeups/assets/88339137/698773bd-c7a3-4b90-907e-fd4e9e985d08)

Don't be fooled into thinking the problematic DLL is `VCRUNTIME140_1.dll` - it
causes an exception because it looks for a non-existing function. However,
vulkan-1 does exist  
in my machine and is successfully loaded (wasn't unloaded). The problem turned
out to be that the application required a different version of vulkan than the
one I had,  
but still expected it to be called `vulkan-1.dll`. Downloading the expected
version of vulkan (and renaming it to vulkan-1.dll to make the program load
it) results in a continuation  
of the execution flow.

![correct_dll_loaded](https://github.com/Om3rR3ich/CTF-
Writeups/assets/88339137/bc474c0d-5cb0-4f0f-a1fd-c9e18eb233a3)

In general, an app will first look up a DLL in its own directory, so whenever
you want to perform a little switcheroo you can simply copy your desired
version  
to the executable's location.

## History is mostly guessing; the rest is prejudice

After fixing the app, running it resulted in the following:

![normal_execution](https://github.com/Om3rR3ich/CTF-
Writeups/assets/88339137/40fb0aea-6733-4abe-9c6c-7b697a59b0e7)

Well, now what?

Since the binary is stripped, the standard approach is to just start at the
beginning (`_start`). This is the first step in a long road of pain and
misery, so I'm going to skip  
that attempt altogether.

Are there any interesting strings (that lead to interesting parts of the
source by an Xref)?  
YES, but for whatever reason (probably an unexpected encoding) IDA couldn't
parse them correctly so they didn't show up.

"Running to user code" also yielded nothing of interest.

With the standard techniques out of the way, we let the guessing game begin!

Fast forward to the one that actually worked, ✨ my intuition ✨ led me to
believe that the flag is hidden somewhere between creating the window (when
the name is still 'RavEngine' - which is the fault),  
and the creation of the graphics. But where is that? Since I couldn't get
there by an Xref from a string, I decided to find the function that's used to
change the title.  
As it turns out, the call to this function is very obfuscated, so looking up
SDL's `SetWindowTitle` (or any of the standard functions) didn't work.

In a moment of clarity, I recalled that flags are fairly commonly hidden in
the TLS of the graphics (or another ) thread, so I looked for an attempt to
access the TLS.  
As a result, discovered the following codeblock:

```cpp  
v21 = (__m128i *)*((_QWORD *)NtCurrentTeb()->ThreadLocalStoragePointer +
(unsigned int)TlsIndex);  
 v22 = v21[6].m128i_i32[2];  
 flag_arr = v21[4].m128i_i8;  
 if ( (v22 & 1) == 0 )  
 {  
   v21[6].m128i_i32[2] = v22 | 1;  
   v21[6].m128i_i8[7] = 1;  
   if ( flag_arr > &v161 || &v21[6].m128i_u16[3] < (unsigned __int16 *)v158 )  
   {  
     *(__m128i *)flag_arr = si128;  
     v21[5] = v20;  
     v21[6].m128i_i32[0] = v159;  
     v21[6].m128i_i16[2] = v160;  
     v21[6].m128i_i8[6] = -45;  
   }  
   else  
   {  
     *(__m128i *)flag_arr = si128;  
     v21[5] = v20;  
     v21[6].m128i_i32[0] = v159;  
     v21[6].m128i_i16[2] = v160;  
     v21[6].m128i_i8[6] = -45;  
   }  
   _tlregdtor(&unk_7FF79A524270);  
 }  
 if ( flag_arr[39] )  
 {  
   *flag_arr ^= 0x8Fu;  
   flag_arr[1] ^= 0xC7u;  
   flag_arr[2] ^= 0xFu;  
   flag_arr[3] ^= 0x57u;  
   flag_arr[4] ^= 0xFDu;  
   flag_arr[5] ^= 0xDBu;  
   flag_arr[6] ^= 0xD3u;  
   flag_arr[7] ^= 0xC7u;  
   flag_arr[8] ^= 0x8Fu;  
   flag_arr[9] ^= 0xC7u;  
   flag_arr[10] ^= 0xFu;  
   flag_arr[11] ^= 0x57u;  
   flag_arr[12] ^= 0xFDu;  
   flag_arr[13] ^= 0xDBu;  
   flag_arr[14] ^= 0xD3u;  
   flag_arr[15] ^= 0xC7u;  
   flag_arr[16] ^= 0x8Fu;  
   flag_arr[17] ^= 0xC7u;  
   flag_arr[18] ^= 0xFu;  
   flag_arr[19] ^= 0x57u;  
   flag_arr[20] ^= 0xFDu;  
   flag_arr[21] ^= 0xDBu;  
   flag_arr[22] ^= 0xD3u;  
   flag_arr[23] ^= 0xC7u;  
   flag_arr[24] ^= 0x8Fu;  
   flag_arr[25] ^= 0xC7u;  
   flag_arr[26] ^= 0xFu;  
   flag_arr[27] ^= 0x57u;  
   flag_arr[28] ^= 0xFDu;  
   flag_arr[29] ^= 0xDBu;  
   flag_arr[30] ^= 0xD3u;  
   flag_arr[31] ^= 0xC7u;  
   flag_arr[32] ^= 0x8Fu;  
   flag_arr[33] ^= 0xC7u;  
   flag_arr[34] ^= 0xFu;  
   flag_arr[35] ^= 0x57u;  
   flag_arr[36] ^= 0xFDu;  
   flag_arr[37] ^= 0xDBu;  
   flag_arr[38] ^= 0xD3u;  
   flag_arr[39] = 0;  
 }  
```

Notice anything suspicious (I put a pretty big hint XD)?

It looks like some chunk of data is extracted from the TLS of the graphics
thread and XORed with hardcoded values.  
The null byte at the end of the byte array is a dead giveaway for a string,
and that string is indeed the flag.  
Place a breakpoint at the end of this codechunk, and examine the memory to
find:

![flag_in_memory](https://github.com/Om3rR3ich/CTF-
Writeups/assets/88339137/d649ebdf-2150-40ad-a6ad-d26d7232f26b)

The (full) flag is: **wctf{your-d3sc3nt-into-gamedev-beg1ns}**  

Original writeup
(https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/game-
graphics-debugging).