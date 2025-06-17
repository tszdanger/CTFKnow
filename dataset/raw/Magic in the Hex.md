# MetaCTF 2021  
## Challenge (100pts)  
### Description:  
>Sometimes in forensics, we run into files that have odd or unknown file
extensions. In these cases, it's helpful to look at some of the file format
signatures to figure out what they are. We use something called "magic bytes"
which are the first few bytes of a file.  
What is the ASCII representation of the magic bytes for a VMDK file? The flag
format will be 3-4 letters (there are two correct answers).

### Step 1 - Resource Gathering:  
We found a [Wikipedia
Page](https://en.wikipedia.org/wiki/List_of_file_signatures) that has a list
of common file signatures. Luckily `VMDK` is on it, so we don't need to look
elsewhere.  
### Step 2 - Identify Magic Bytes:  
According to the Wikipedia page, `VMDK` files have 3 short ASCII bytes, which
is what the flag is looking for.  
<details>  
 <summary> Flag Spoiler </summary>  
 KDM  
</details>

## Learning Takeaways  
We learn about magic bytes and file identifiers in this challenge to discern
what a file is. Many applications use this to identify a file rather than
observing its contents, which can allow for steganographic techniques.  

Original writeup
(https://github.com/team23ctf/writeups/blob/main/metactf2021/Magic%20in%20the%20Hex/Magic%20in%20the%20Hex.md).