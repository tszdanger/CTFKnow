Full solution in the link:  [http://github.com/TheMaccabees/ctf-
writeups/blob/master/DragonCTF2021/ShellcodeVerifier/solution](http://github.com/TheMaccabees/ctf-
writeups/blob/master/DragonCTF2021/ShellcodeVerifier/solution)  
```  
// Exploit strategy:  
// We rely on a documented mmap bug (see "man 2 mmap") regrading the file page
cache.  
// Let's quote from the man:  
//     POSIX specifies that the system shall always zero fill any partial page
at the end of  the  
//     object and that system will never write any modification of the object
beyond its end.  On  
//     Linux, when you write data to such partial page after the end  of  the
object,  the  data  
//     stays  in  the  page  cache even after the file is closed and unmapped
and even though the  
//     data is never written to the file itself, subsequent mappings may see
the  modified  con‐  
//     tent. [...]  
//  
// Because 'mmap' works on page-granularity, we can abuse this bug in order to
pass verification.  
// We abuse the flow in "exec_output": the size of the file is obtained by
'fstat' and passed to  
// the shellcode verifier, but the whole page is mmap-ed and later executed.
Because we abuse the  
// mmap page cache bug, we can make sure there are more controlled bytes past
the verified  
// shellcode - which will be executed but won't be verified.  
//  
// So the general flow we run in the compiler:  
// 1. Create "prog" file, write a single "nop" instruction (0x90) into it.  
// 2. sleep() for a little (maybe not needed - just solved some problems in
practice)  
// 3. mmap the "prog" file, and write past the nop instruction our
execve("/bin/sh") shellcode.  
// 4. exit() right away. The sandbox process will now continue.  
// 5. In the sandbox, 'exec_output' will only verify the "nop", but will
execute the entire shellcode.  
// 6. ???  
// 7. PROFIT  
```  

Original writeup (https://github.com/TheMaccabees/ctf-
writeups/blob/master/DragonCTF2021/ShellcodeVerifier/solution/compiler/compiler.c#L21).