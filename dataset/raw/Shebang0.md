# shebang0 | Points:125  
Challenge description:  
> Welcome to the Shebang Linux Series. Here you will be tested on your basic
> command line knowledge! These challenges will be done threough an ssh
> connection.  
>  
> Also please do not try and mess up the challenges on purpose, and report any
> problems you find to the challenge author. You can find the passwords at  
>  
> /etc/passwords. The username is the challenge title, shebang0-5, and the
> password is the previous challenges flag, but for the first challenge, its
> shebang0  
>  
> The first challenge is an introductory challenge. Connect to
> cyberyoddha.baycyber.net on port 1337 to recieve your flag!

1)Connect using the given credentials  
> ssh [email protected] -p 1337  
>  
> Password: shebang0

2)You'll be prompted something like this  
>  shebang0@c18466cfac18:~$

3)First i tried --> __ls__ command, but it didn't worked

4)So i used __ls -la__

> Note: ls -la is used to list all the files including hidden files also

5)There is a hidden file named __.flag.txt__

6)Using cat command open the file  
> cat .flag.txt

7)Hurrah we found the flag!!!  
> Flag:CYCTF{w3ll_1_gu3$$_b@sh_1s_e@zy}

Happy hacking!!!  

Original writeup
(https://github.com/UVvirus/writeups/tree/main/shebang/shebang0).