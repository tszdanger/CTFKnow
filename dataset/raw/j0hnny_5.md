```  
$ cat clue.txt  
Sentience is an abstract concept...  
```

Notice that task theme is the Short Circuit movie.

Look for open ports

```  
$ netstat -aepW  
Active UNIX domain sockets (servers and established)  
Proto RefCnt Flags       Type       State         I-Node PID/Program name
Path  
unix  2      [ ACC ]     STREAM     LISTENING      30920 -
@?  
```

The one listening is a unix socket in the abstract namespace (not bound to
file system).

Scripting is available with `python`. And you can find a writable folder, if
you need one.  
`wget` is available to download scripts.

Connect to the socket, the address is `\x00?`:

```  
_______   _____  
|  ___ \ / ___ \| |  | |/\  
| |   | | |   | | |  | /  \  
| |   | | |   | |\ \/ / /\ \  
| |   | | |___| | \  / |__| |  
|_|   |_|\_____/   \/|______|  
		     |      |  
	    _                _  
	   | |          _   (_)  
 ____ ___ | | _   ___ | |_  _  ____  ___  
/ ___) _ \| || \ / _ \|  _)| |/ ___)/___)  
| |  | |_| | |_) ) |_| | |__| ( (___|___ |  
|_|   \___/|____/ \___/ \___)_|\____|___/  
			 Tomorrow is Here.

Welcome to the Nova Robotics Satellite debug interface

> help  
=-=>>>> Connected to Robot[5]["Nickname"]: J0hnny F1ve  
Current functions: list, test, command. Use "help <cmd>" for more information.

> list  
Function list is: help, list, test, command

> help command  
Issue a command

> command  
Error: missing argument. Supported commands are: access_code, self_destruct

> command self_destruct  
:( .... I am ALIVE!

> command access_code  
must supply unlock code

> command access_code 1337  
ACCESS DENIED but a hint: you may need to watch a movie, youtube or otherwise
obtain words.  
```

Remember the theme? The access code used in the movie:

```  
> command access_code 42721  
Access gained. Number FIVE

> help  
Current commands: list, test, command, execute, self_destruct, show, download,
upload. Use "help <cmd>" for more information.  
```

```  
> help show  
List a directory or the default folder

> show  
novarobotics.j5v1.1.bin  
novarobotics.j5v1.0.bin

> help upload  
Upload listing and upload firmware update to the target directory

> upload novarobotics.j5v1.0.bin  
Upload error: Malfunction  
```

`show` and `upload` are vulnerable to path traversal:

```  
> show ../../  
/bin  
/boot  
/dev  
/etc  
/home  
malfunction  
malfunCTION  
/nova  
maLfucti0n  
END firmware list: Malfunction detected

> upload ../../nova/  
Upload Fatal: Gibson server returned: error! ../../nova/tmp/ is not empty

> upload ../../nova/tmp/  
Upload Fatal: Gibson server returned:  
.garbage/

> upload ../../nova/tmp/.garbage/  
MalfUncTiON  
novarobotics.j5_jailbroken.bin  
```

We have found some firmware. Upload it into robot:

```  
> help download  
Download and stage a firmware update

> download ../../nova/tmp/.garbage/novarobotics.j5_jailbroken.bin  
Download succeeded. Response is: update_staged.

> show  
novarobotics.j5_jailbroken.bin

> help execute  
Supply a firmware update related command

> execute update  
----------------  
Performing Firmware UpdaMalFucTiOn  
M4lfuct1on  
malfunction  
Malfunction detected  
Update error code: -2319  
return string from robot:  
fb{flag}  
```