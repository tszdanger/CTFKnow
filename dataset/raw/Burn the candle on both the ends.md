## Burn The Candle On Both Ends - Forensics 150:  

**Description:** It's a two step problem  
**Challenge:** candle.jpg  
**Difficulty:** Easy  
**Solved by:** Eric & Tahar  

**Solution:**  
Downloaded the challenge file and used the **file** command in the Linux
terminal to identify it! It was a normal JPG Image!  
By using the famous forensics toolkit **Binwalk** we find an interesting ZIP
file embeded into the main challenge file!  
```binwalk candle.jpg```  

We start by extracting that ZIP file from the challenge file, we have too many
tricks to do that, we can use a **Hex Editor** and get out the hex data into a
new zip file or we can use **DD** or just the same toolkit **Binwalk** or by
using **Foremost** (another well known digital forensics tool). By using
**Binwalk** we use the following command:  
```binwalk -e candle.jpg```  

After, that we got an **Encrypted ZIP Archive**, the description did not say
anything, but it mentioned that this a Two Step challenge, so we done the
first step which is extracting the Hidden ZIP File! And the second step is
probably bruteforcing that ZIP Archive!!  

We use the well known **Rockyou Wordlist** to bruteforce the ZIP Archive,
**fcrackzip** did not work, so we thought about using another well known
toolkit under the name of **John The Ripper** it is a well known password &
hash cracking toolkit!  
We used a toolkit **zip2john** to get the hash of that ZIP Archive using the
command: ```zip2john archive.zip > hash.txt```  

Then, we got a HASH, time to crack it using **Rockyou & John**. We run the
following command to launch the **BruteForce Attack**: ``` john
--wordlist=rockyou.txt --format=zip hash.txt```  

Successsful Attack, password: **stegosaurus**  

Now, it is time to grab the flag by extracting the **flag.txt** file from the
Decrypted ZIP Archive =)

**Flag:**  
RITSEC{8U51N355–1N-7H3-Fr0N7-P4r7Y-1N-7H3–84CK}  

Original writeup
(https://github.com/ImperiumCTF/Writeups/blob/master/RITSEC%20CTF%202018/Forensics/Burn_The_Candle_On_Both_Ends.md).