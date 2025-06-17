**Description**

> Run it and get flag (but how?) (segfault is NOT a bug)  
>  
> attachment: https://drive.google.com/open?id=1ghFVktqDYM48YiJt-ppx6a-2JHH-
> wIKm

**Solution**

Apparently the simplest challenge of the CTF, the executable seems to contain
the wine runtime and some emulated Windows functions, dialogs, Notepad stuff
...? Perhaps it runs properly on a Linux desktop with a graphical environment
/ X11?

For my actual solution however, I loaded the executable into radare and after
analysing the functions with `aaa`, `afl` produced:

   0x7f7f96534000    8 192  -> 194  obj.imp.__wine_main_argv  
   0x7f7f96545cd0    1 6            sym.imp.__wine_dll_register  
   0x7f7f96545ce0    1 6            sym.imp.__stack_chk_fail  
   0x7f7f96545cf0   21 270  -> 256  entry0  
   0x7f7f96545e00    3 33           sub._ITM_deregisterTMCloneTable_e00  
   0x7f7f96545e70    4 50           entry2.fini  
   0x7f7f96545eb0    5 5    -> 56   entry1.init  
   0x7f7f96545ec8    1 6            fcn.7f7f96545ec8  
   ...  
   0x7f7f96546238    1 6            fcn.7f7f96546238  
   0x7f7f96546481    5 256          sym.ShowLastError  
   0x7f7f96546581    6 295          sym.UpdateWindowCaption  
   0x7f7f965466a8    8 359          sym.DIALOG_StringMsgBox  
   0x7f7f96546a32    3 129          sym.FileExists  
   0x7f7f96547074   14 208          sym.DoCloseFile  
   0x7f7f965471fa   47 1579         sym.DoOpenFile  
   0x7f7f96547825    3 121          sym.DIALOG_FileNew  
   ...  
   0x7f7f96549e44    1 65           sym.DIALOG_FilePageSetup  
   0x7f7f9654a192    1 124          sym.SetFileNameAndEncoding  
   0x7f7f9654a20e    9 195          sym.get_dpi  
   0x7f7f9654bb68   17 684          sym.NOTEPAD_DoFind  
   0x7f7f9654ce46   18 1356         sym.WinMain  
   0x7f7f9654fff8    1 8            reloc.__cxa_finalize

Of interest was really mainly `sym.WinMain`, so with `pdf @ sym.WinMain`, I
found a line that said:

   ...  
   |      |    0x7f7f9654d263      488b4018       mov rax, qword [rax + 0x18] ; [0x18:8]=-1 ; 24  
   |      |    0x7f7f9654d267      488d159a0800.  lea rdx, str.RCTF_WelCOme_To_RCTF ; 0x7f7f9654db08 ; u"RCTF{WelCOme_To_RCTF}\n\n\u5700\u6168\u3f74\u5920\u756f\u6420\u6365\u6d6f\u6970\u656c\u2064\u656d\u3f3f"  
   |      |    0x7f7f9654d26e      4889c1         mov rcx, rax  
   ...

And there was the flag:

`RCTF{WelCOme_To_RCTF}`

In fact, the flag was available in plaintext in the binary, but e.g. `strings`
could not find it - it was encoded as UTF-16, taking two bytes per character.
This is typical for Windows binaries, which is probably why this challenge
used this setup.

Original writeup
(https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-19-RCTF/README.md#73-misc
--sign).