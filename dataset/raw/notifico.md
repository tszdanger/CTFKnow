**Description**

> veni, vidi, notifici  
>  
> Notes: - only chmod, no touch - no root user, please - tar --no-same-owner
> -xhzf chall.tar.gz  
>  
> [Challenge
> files](https://archive.aachen.ccc.de/35c3ctf.ccc.ac/uploads/notifico-b568d7b9b60a42e7e06471e2f9cb0883.tar.gz)  
>  
> **HINT**: The graph is a move graph for a certain type of chess piece.

**Files provided**

- [notifico.tar.gz](https://archive.aachen.ccc.de/35c3ctf.ccc.ac/uploads/notifico-b568d7b9b60a42e7e06471e2f9cb0883.tar.gz)

**Solution**

In the `tar` archive, we see three files:

- `chall.tar` - another archive containing 225 directories with some 40-50 files each, although all but one in each directory are symlinks  
- `check.py` - flag decryption script invoking `check` in the process  
- `check` - ELF executable to verify a given directory

The first step was to look into `check.py`. The important bit was:

```python  
VAL = 15

# ...

res = subprocess.call(["./check", basedir])

if res == 255 or res != VAL:  
   print("This looks no good...")  
   exit(-1)  
else:  
   print("A worthy try, let's see if it yields something readable...")  
```

So whatever directory we give it as our "solution", it will invoke the `check`
executable on it. `check` in turn must return `VAL`, i.e. `15` for the
solution to be considered valid. The SHA-256 hash of the UNIX permissions of
the files in our solution directory is then used to decrypt a flag encrypted
using AES. Given that there are `225` "regular" files and hundreds of symlinks
in the `chall.tar` archive which forms the template for our solution, brute-
force is infeasible.

The hint given in the challenge description spoils what `chall.tar` is
completely, so much so that I am surprised this challenge didn't have many
more solutions after the hint was released. We can gain a similar
understanding of `chall.tar` from how the `check` executable works and the
general structure of the archive.

Using IDA Pro we can find that `check` does roughly the following:

- sets up `inotify` watchers on all regular (non-symlink) files in each of the `225` directories  
- try to `fopen` each of the `225` regular files in read/write mode, then `fclose`  
- set `result` to `0`  
- handle all triggered `inotify` events:  
  - increment `result` by `1`  
  - for each `IN_CLOSE_WRITE` event (i.e. file closed after write access), try to `execve` all the symlinks in the just-closed file's directory  
- exit with exit code `result`

Note that `execve` will only succeed when the file referenced by the symlink
can be executed; if `execve` succeeds, the program will crash, because there
are no valid executables in the `chall.tar` directory (each regular file is
only 1 byte long).

In other words, `check` counts the regular files it can open whose
"neighbours" (i.e. files referenced by the symlink it that file's directory)
are not executable.

One more extremely important hint: the number of directories in `chall.tar` is
`225`, which is `15 * 15`, a perfect square. `VAL` is also `15`.

We can also count how many files there are in each of the `225` directories.
If we simply extract the archive and go through the directories in
alphabetical order, the result is rather chaotic. However, the directories are
contained in `chall.tar` in a particular order. We can see this with:

```bash  
$ tar -tvf chall.tar  
drwxr-xr-x  0 notifico notifico    0 Dec 22 14:06 chall/  
drwxr-xr-x  0 notifico notifico    0 Dec 22 14:06 chall/NrTOYjZgBjJHfNLu/  
lrwxrwxrwx  0 notifico notifico    0 Dec 22 14:06
chall/NrTOYjZgBjJHfNLu/clxAKWStzqRKyxql ->
../eAvSLhONEWpXqnwu/JHFulfjgaQGnmOPx  
lrwxrwxrwx  0 notifico notifico    0 Dec 22 14:06
chall/NrTOYjZgBjJHfNLu/OfTFUEFIyGMZMoan ->
../HdWkyeWugdUHdzuU/rUXgDUpTytwSoWon  
lrwxrwxrwx  0 notifico notifico    0 Dec 22 14:06
chall/NrTOYjZgBjJHfNLu/drwKLoWvVcjNdMiX ->
../zoPhogrElBntiQUN/ThQhbYJgbiSZbykb  
lrwxrwxrwx  0 notifico notifico    0 Dec 22 14:06
chall/NrTOYjZgBjJHfNLu/zvXOjUgOepbQeCoe ->
../ISOYfrwvVOMZveHE/jroOyZVjiUCJCHgf  
...  
...  
...  
lrwxrwxrwx  0 notifico notifico    0 Dec 22 14:06
chall/fXWIMMRZvMSweIId/GIlMJUgUbXbYmdSE ->
../pNuhEkCjuZfTZWvi/JFhCuAbdlsMRpcNo  
lrwxrwxrwx  0 notifico notifico    0 Dec 22 14:06
chall/fXWIMMRZvMSweIId/KdDQXPXYBqQARKQc ->
../QdyTwLeNTUDvXTFI/DJLuDDWviVrYegVM  
lrwxrwxrwx  0 notifico notifico    0 Dec 22 14:06
chall/fXWIMMRZvMSweIId/MCOiuhLUCuCoPZvn ->
../vruPGIPvYbkWqNzX/MHinNnRcKtLLeEXV  
lrwxrwxrwx  0 notifico notifico    0 Dec 22 14:06
chall/fXWIMMRZvMSweIId/ufIYqBqbfCgGIspR ->
../vqPxvKvBQGHntyiv/aYPWRwJUyOyHRILd  
-r--------  0 notifico notifico    1 Dec 22 14:06 chall/fXWIMMRZvMSweIId/KYtdUumqvnfClEMF  
```

If we count the symlinks in the directories in this order and arrange them in
a `15 * 15` square, we get a very neat result:

   42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42  
   42,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  42  
   42,  44,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  44,  42  
   42,  44,  46,  48,  48,  48,  48,  48,  48,  48,  48,  48,  46,  44,  42  
   42,  44,  46,  48,  50,  50,  50,  50,  50,  50,  50,  48,  46,  44,  42  
   42,  44,  46,  48,  50,  52,  52,  52,  52,  52,  50,  48,  46,  44,  42  
   42,  44,  46,  48,  50,  52,  54,  54,  54,  52,  50,  48,  46,  44,  42  
   42,  44,  46,  48,  50,  52,  54,  56,  54,  52,  50,  48,  46,  44,  42  
   42,  44,  46,  48,  50,  52,  54,  54,  54,  52,  50,  48,  46,  44,  42  
   42,  44,  46,  48,  50,  52,  52,  52,  52,  52,  50,  48,  46,  44,  42  
   42,  44,  46,  48,  50,  50,  50,  50,  50,  50,  50,  48,  46,  44,  42  
   42,  44,  46,  48,  48,  48,  48,  48,  48,  48,  48,  48,  46,  44,  42  
   42,  44,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  44,  42  
   42,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  42  
   42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42

It is symmetric and there are more symlinks in the "central" directories.

Maybe you can see where all of this (+ the explicit hint) is leading to.
Chess! More specifically, a chess puzzle, the [N queens
problem](https://en.wikipedia.org/wiki/Eight_queens_puzzle). The famous eight
queens puzzle is a chess puzzle where the goal is to arrange `8` queens on a
regular (`8 * 8`) chessboard without any of them being able to see one another
(queens can move and see horizontally, vertically, and diagonally). In this
case we have a `15` queens puzzle.

Consider for example the top-left directory in the table above. It has `42`
symlinks:

   Q,   X,   X,   X,   X,   X,   X,   X,   X,   X,   X,   X,   X,   X,   X  
   X,   X,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .  
   X,   .,   X,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .  
   X,   .,   .,   X,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .  
   X,   .,   .,   .,   X,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .  
   X,   .,   .,   .,   .,   X,   .,   .,   .,   .,   .,   .,   .,   .,   .  
   X,   .,   .,   .,   .,   .,   X,   .,   .,   .,   .,   .,   .,   .,   .  
   X,   .,   .,   .,   .,   .,   .,   X,   .,   .,   .,   .,   .,   .,   .  
   X,   .,   .,   .,   .,   .,   .,   .,   X,   .,   .,   .,   .,   .,   .  
   X,   .,   .,   .,   .,   .,   .,   .,   .,   X,   .,   .,   .,   .,   .  
   X,   .,   .,   .,   .,   .,   .,   .,   .,   .,   X,   .,   .,   .,   .  
   X,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   X,   .,   .,   .  
   X,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   X,   .,   .  
   X,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   X,   .  
   X,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   .,   X

Count the squares that the queen (`Q`) can see (`X`) and there are 42 of them.
In fact, each of those `X`'s in the actual `chall.tar` is a symlink to that
particular directory.

Unfortunately, there are thousands of solutions to the 15 queens problem.
Fortunately, we can generate them systematically with a script and hence
decrypt the flag. Once again, we can adapt a program from [Rosetta
Code](http://rosettacode.org/wiki/N-queens_problem).

[Adapted C program
here](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-12-27-35C3-CTF/scripts/queens.c)

We let this C program generate all the solutions to the problem and have a
Python script change each solution to a list of UNIX permissions in the order
the original `check.py` script used (it sorted the directories
alphabetically), SHA-256 hash it, and try to decrypt the flag.

[Python decoder
here](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-12-27-35C3-CTF/scripts/queens.py)

(As per the challenge description, each "queen" would be marked by a regular
file with `700` permissions, each non-queen would remain at `400` permissions,
as provided in the `chall.tar` template.)

`35C3_congr4ts_th0se_were_s0m3_truly_w3ll_pl4c3d_perm1ssions_Sir_`  

Original writeup
(https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-12-27-35C3-CTF/README.md#215-rev
--notifico).