## Obliterated Again  
Description:

I realized that the previous command had a mistake. It should be right this
time...?

```bash  
$ git filter-branch --index-filter "git rm -f --ignore-unmatch *flag" --prune-
empty -- --all  
$ git reflog expire --expire=now --all  
$ git gc --aggressive --prune=now  
```

Using `git log` and `git show` didn't find anything

I google about "git restore after git filter-branch", I found something in
[this link](https://stackoverflow.com/questions/14542326/undo-git-filter-
branch)

After running `git reset --hard refs/original/refs/heads/master` command, we
get the flag back!  
```bash  
root@2Real:~/Downloads/TSGCTF/Obliterated_again/easy_web# git reset --hard
refs/original/refs/heads/master  
HEAD is now at 1c80e25 enable production mode  
root@2Real:~/Downloads/TSGCTF/Obliterated_again/easy_web# ls  
problem  README.md  
root@2Real:~/Downloads/TSGCTF/Obliterated_again/easy_web# cd problem/  
root@2Real:~/Downloads/TSGCTF/Obliterated_again/easy_web/problem# ls  
data.db  flag  lib  main.cr README.md  shard.lock  shard.yml  src  
```  
Using the same script:  
```python  
import zlib  
f = open('easy_web/problem/flag')  
print zlib.decompress(f.read())  
```

## Flag  
> TSGCTF{$_git_update-ref_-
> d_refs/original/refs/heads/master_S0rry_f0r_m4king_4_m1st4k3_0n_th1s_pr0bl3m}

Original writeup
(https://github.com/Hong5489/TSGCTF2019/tree/master/Obliterated_again).