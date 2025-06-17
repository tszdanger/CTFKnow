# ASIS CTF quals 2018 - Task "Tokyo"

In this task we are provided a single binary file in a format that is  
not recognized by either `file` or `binwalk`.

## Investigating the file format

Before knowing the format thanks to the hint, we could guess some  
characteristics of the file:

- There's a header beginning with KC and several values from where  
it's not evident to extract any information, pointing to some real  
life database format, and not something made just for this task.  
We searched for it but sadly we didn't find any matching well-known  
format.

- Then there's a section of 6 MB which is mostly filled with zeros,  
but with some values that appear from time to time:

```  
00095260  00 00 00 00 00 00 00 00  00 00 00 0c 03 30 00 00  |.............0..|  
001d9a90  00 00 00 0c 03 51 00 00  00 00 00 00 00 00 00 00  |.....Q..........|  
004165a0  00 00 00 00 00 00 00 0c  03 72 00 00 00 00 00 00  |.........r......|  
```

These values go from 0x0c030f (787215) to 0x0c0417 (787479),  
increasing 3 by 3 for a total of 89 values. Their position  
within the 6 MB section don't follow any pattern, which  
probably means it's something to take into account.

- At the end of the file there's a smaller section with this aspect:

```  
00601d40  cc 04 00 00 00 00 00 00  00 00 00 00 00 00 03 01  |................|  
00601d50  00 00 00 7b ee 00 00 00  cc 04 00 00 00 00 00 00  |...{............|  
00601d60  00 00 00 00 00 00 03 01  00 00 00 53 ee 00 00 00  |...........S....|  
00601d70  cc 04 00 00 00 00 00 00  00 00 00 00 00 00 03 01  |................|  
00601d80  00 00 00 5f ee 00 00 00  cc 04 00 00 00 00 00 00  |..._............|  
00601d90  00 00 00 00 00 00 03 01  00 00 00 72 ee 00 00 00  |...........r....|  
```

It's a sequence of 24 byte blocks, with one letter/symbol on each block.  
Extracting them we get a list of 89 characters (matching the 89 values  
in the first section):

```  
!_Ab_ni!_as__ial_Cb_a_iSgJg_td_eKeyao_ae_spb}iIyafa{S_r__ora3atnsonnoti_faon_imn_armtdrua  
```

It clearly looks the flag but unordered. But it's too long to attempt  
guessing or brute forcing it, so we tried to get some clues from the  
89 values in the first section of the file.

We assumed that those 89 values are references pointing to the 89  
characters in the second section, so 0x0c030f (787215) would point  
to !, 0x0c0312 to \_, 0x0c0315 to A, and so on

But after trying some combinations (e.g. taking the letters pointed  
by the references in the same order as they appear in the first  
section), no solution was obtained and we were stuck.

## Kyoto Cabinet

Then the hint arrived (no solves yet at this time) in the form of  
"Kyoto Cabinet", and we could then understand that the file was  
actually a DBM-like database in Kyoto Cabinet format (a successor  
of Tokyo Cabinet), which is an efficient key/value database format.

With the proper tools we could get more information on the file  
format. Traversing all key/values would show that the values were,  
as expected, the unordered letters of the flag, but also that they  
all had a three byte null (0x000000) key!

We could also look at what happens when a new key/value pair is  
added to the database:

```bash  
$ kchashmgr set tokyo k1 val1  
```

```  
@@ -211,6 +211,10 @@  
+00483770  00 0c 04 1a 00 00 00 00  00 00 00 00 00 00 00 00
|................|  
@@ -416,4 +420,6 @@  
+006020d0  cc 02 00 00 00 00 00 00  00 00 00 00 00 00 02 04
|................|  
+006020e0  6b 31 76 61 6c 31 ee 00                           |k1val1..|  
```

Now we got something! In the first section there's a new value  
0x0c041a, which is exactly 3 higher than the previous last one  
(0x0c0417), confirming us these values are references to the  
entries in the second section.

Taking into account this is a hash based DBM, it looks the first  
section is a fixed size hash table, meaning that the position where  
references are stored are just the result of the hash function over  
the stored keys.

In the second section we get now a new 24 bytes block, and we can  
see that both the key (k1) and the value (val1) appear together.  
We can also see that the previous bytes (0x02 and 0x04) indicate  
the length of the key and the length of the value (this explains  
the 0x03 for the key and 0x01 for the value in the rest of entries  
corresponding to the flag characters)

## Sorting the flag characters

So it seems the flag characters have been inserted with some three  
byte keys (which probably determine the order) but the keys have  
been deliberately removed. We need to recover them to obtain back  
the missing information we need to sort the flag characters.

We just need to find a key that, when inserted in the kc file,  
overwrites one of the current references (assuming there won't be  
any collision, but it's too sparse)

Keys are just 3 bytes long, so bruteforcing them would have worked,  
but we attempted some educated guessing first: maybe they keys are  
just "000", "001", "002"...? Let's try that:

```bash  
$ kchashmgr set tokyo 000 "value"  
```

```  
-005a9b90  00 00 00 00 00 00 00 0c  03 15 00 00 00 00 00 00  |................|  
+005a9b90  00 00 00 00 00 00 00 0c  04 1d 00 00 00 00 00 00
|................|  
```

Gotcha! Writing the key "000" has overwritten the old reference  
pointing to 0x0c0315, which corresponds to the character 'A',  
matching the beginning of ASIS flags.

We just need to add the rest of the keys one by one, checking which  
references they overwrite and the character pointed by them, and we  
get the full key:

```  
ASIS{Kyoto_Cabinet___is___a_library_of_routines_for_managing_a_database_mad3_in_Japan!_!}  
```  

Original writeup (https://github.com/netsuso/ctf-
writeups/tree/master/asis-2018-quals/tokyo).