# Description

### Title: Corruption

It seems that this remote is somehow corrupted. See if we can somehow get the
data...

git://git.ritsec.club:9418/corruption.git

# Solution

When cloning the repo, you will see that it fails. What actually happens is
that the as much of the repo as possible is downloaded, but this is then
deleted (since fetching the rest of the repo fails thanks to the corruption).
The cloning error that is returned indicates that it is most likely due to
compression issues and the presence of an extremely large file on the remote
side.

So my hacky solution was to copy and paste the fetched `.git` folder before it
was deleted. Try running `git fetch --all` to fetch the rest of the files. It
doesn't work, so we have to something else. `cd` to the `.git` folder and edit
the git `config` file to change `fetch = +refs/heads/*:refs/remotes/origin/*`
to `fetch = +refs/heads/master:refs/remotes/origin/master`. This will only
fetch files from the master branch for now, since it might be fine and some
other branch might be corrupted.

Then run `git fetch --all` to fetch files from the master branch. Run `git
log` to see commit history, but you'll see that it doesn't work. Run `git
fsck` to see what issues might be causing this. You'll get: `dangling blob
c09b32987380e63e93d93f699e1dbfeae839f8e2`.

Let's see what this is. Run `git show
c09b32987380e63e93d93f699e1dbfeae839f8e2`. You'll get the flag.

### Flag

`RS{se3_that_wasnt_s0_bad_just_som3_git_plumbing}`  

Original writeup (https://github.com/black-tul1p/CTF-
Writeups/tree/main/RITSEC-2021/misc/Corruption).