# Obliterated File  
```bash  
※ This problem has unintended solution, fixed as "Obliterated File Again".
Original problem statement is below.

Working on making a problem of TSG CTF, I noticed that I have staged and
committed the flag file by mistake before I knew it. I googled and found the
following commands, so I'm not sure but anyway typed them. It should be ok,
right?

$ git filter-branch --index-filter "git rm -f --ignore-unmatch problem/flag"
--prune-empty -- --all  
$ git reflog expire --expire=now --all  
$ git gc --aggressive --prune=now  
```  
[problem.zip](problem.zip)

Unzip it  
```bash  
root@2Real:~/Downloads/TSGCTF/Obliterated# ls  
easy_web  problem.zip  
root@2Real:~/Downloads/TSGCTF/Obliterated# ls -la easy_web/  
total 52  
drwxr-xr-x 5 root root 4096 May  6 12:54 .  
drwxr-xr-x 3 root root 4096 May  5 03:42 ..  
-rw-r--r-- 1 root root  150 Apr 30 16:20 .editorconfig  
-rw-r--r-- 1 root root   62 May  5 03:38 flag  
drwxr-xr-x 7 root root 4096 May  6 12:54 .git  
-rw-r--r-- 1 root root   46 May  5 03:38 .gitignore  
-rw-r--r-- 1 root root  427 May  5 03:38 main.cr  
drwxr-xr-x 4 root root 4096 May  6 12:54 problem  
-rw-r--r-- 1 root root   64 May  2 04:45 README.md  
-rw-r--r-- 1 root root  507 May  5 03:38 shard.lock  
-rw-r--r-- 1 root root  297 May  5 03:38 shard.yml  
drwxr-xr-x 4 root root 4096 May  5 03:38 src  
-rw-r--r-- 1 root root   18 May  5 03:38 .travis.yml  
```  
Looks like a git repository

Using `git log` to view prevoius commit  
```bash  
root@2Real:~/Downloads/TSGCTF/Obliterated/easy_web# git log | grep commit  
commit 266f4148e4cf37bdbfb57da379ea49b2f106e6b2  
commit cd50304fc39f8c0fbc7ad062ecb9a940f3baed29  
commit ba46709ec62fd916b29f17c5e9fd2fa99b71027c  
commit d516014b8de3f20d473f2adca1713337095c7873  
commit 98d396f94fb23e9e0fb317aa041ca02691f7ec8b  
commit 28d2b74b0c40583a87cf275f9f0cdfd55042884d  
commit 84128ed70713706bef35805b2a097c1e5b493277  
commit 39aa6c95cc229e828f4fb5115c2396c0a841eed4  
commit 6b4cbce5f389a45bc849f07fa5c17a8b7f43f005  
commit bff308624444eed4cac43b0d432a92d2d350fcfb  
commit f4416accd32d3063630d243770ff6d1ba79ac209  
commit b346b76e3642b0b33f5b17a19761b8d77276473b  
commit b614e74c0d6db7c50c64a6f643c08e768308295c  
commit 828b54e76c9ee94b1d9a478aef792726c60a01bc  
commit 0f0a48cede1c8edb37b9449b7de0eb28402db1fc  
commit 166baf8b5abaf404923426c08199e7396628e759  
commit 4801d6ec013679a4cd8353812fa9502418ba6237  
commit d3953a7e9d5e89a07f767851721c09b543fe1a9b  
```  
Using `git show <commit hash>` to view the committed content:  
```bash  
root@2Real:~/Downloads/TSGCTF/Obliterated/easy_web# git show
ba46709ec62fd916b29f17c5e9fd2fa99b71027c  
commit ba46709ec62fd916b29f17c5e9fd2fa99b71027c  
Author: tsgctf <[email protected]>  
Date:   Thu May 2 18:37:22 2019 +0900

   fix .gitignore

diff --git a/problem/.gitignore b/problem/.gitignore  
index 94ae2db..4e48cb9 100644  
--- a/problem/.gitignore  
+++ b/problem/.gitignore  
@@ -4,4 +4,4 @@  
/.shards/  
*.dwarf  
*.db  
-falg  
\ No newline at end of file  
+flag  
\ No newline at end of file  
```  
When viewing commit `28d2b74b0c40583a87cf275f9f0cdfd55042884d`, I show
something interesting  
```bash  
commit 28d2b74b0c40583a87cf275f9f0cdfd55042884d  
Author: tsgctf <[email protected]>  
Date:   Thu May 2 05:45:41 2019 +0900

   add problem statement

diff --git a/README.md b/README.md  
index 60723b1..6eec6e5 100644  
--- a/README.md  
+++ b/README.md  
@@ -1,7 +1,5 @@  
# easy_web  
  
-TODO: Write a description here  
+## Problem Statement  
  
-## Usage  
-  
-TODO: Write usage instructions here  
+The flag is admin's password.  
diff --git a/flag b/flag  
deleted file mode 100644  
index 111eb96..0000000  
...  
...  
...  
```  
At this commit, it deleted the `flag` file

We can use `git revert` command to get back the previous commited file:  
```bash  
# git revert 28d2b74b0c40583a87cf275f9f0cdfd55042884d  
[master ae6feec] Revert "add problem statement"  
12 files changed, 4 insertions(+), 2 deletions(-)  
create mode 100644 flag  
rename problem/main.cr => main.cr (100%)  
rename problem/shard.lock => shard.lock (100%)  
rename problem/shard.yml => shard.yml (100%)  
rename {problem/src => src}/app.cr (100%)  
rename {problem/src => src}/public/css/.gitkeep (100%)  
rename {problem/src => src}/public/js/.gitkeep (100%)  
rename {problem/src => src}/views/index.ecr (100%)  
rename {problem/src => src}/views/layout.ecr (100%)  
rename {problem/src => src}/views/login.ecr (100%)  
rename {problem/src => src}/views/register.ecr (100%)  
root@2Real:~/Downloads/TSGCTF/Obliterated/easy_web# ls  
flag  main.cr  problem  README.md  shard.lock  shard.yml  src  
```  
Yeah! We get back the flag file!

Lets see what's inside:  
```bash  
root@2Real:~/Downloads/TSGCTF/Obliterated/easy_web# cat flag  
x�  
        vwq�V�O�,�/-HI,I�-JM��M�R���E���y�9�`^FjbJ�~nbqIjQ-��?(  
root@2Real:~/Downloads/TSGCTF/Obliterated/easy_web# file flag  
flag: zlib compressed data  
```  
It's a zlib file

We can use python script to decompress it:  
```python  
import zlib  
f = open('easy_web/flag')  
print zlib.decompress(f.read())  
```  
[My script here](solve.py)

And we get the flag!  
```bash  
# python solve.py  
TSGCTF{$_git_update-ref_-d_refs/original/refs/heads/master}  
```

## Flag  
> TSGCTF{$_git_update-ref_-d_refs/original/refs/heads/master}

Original writeup
(https://github.com/Hong5489/TSGCTF2019/tree/master/Obliterated).