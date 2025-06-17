**Description**

> I found this strange string of numbers inside a copy of Отцы и дети by Ива́н
> Серге́евич Турге́нев that Cypher left inside a postbox. Can you help me
> figure out what it is? NOTE: the flag is not encoded in the usual format,
> enter it as sctf{FLAG} with the flag in caps

**Files given**

- `emsg.tar.gz` - containing the cipher text [`emsg.txt`](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-31-SecurityFest/scripts/note/emsg.txt), with 682 pairs of decimal digits separated by spaces

**Solution**

Given the hint mentioning a book and the cipher text being small numbers, my
first thought was that this is a book cipher. I made several attempts:

- using the original Russian text  
  - number = word in text, take first letter of word  
  - number = letter in text  
- same with English text

But all of it looked rather nonsensical. At this point there were still no
solves, and the admin of the challenge hinted that "knowing what the book was
about is useful". So having a look at the [Wikipedia
page](https://en.wikipedia.org/wiki/Fathers_and_Sons_(novel)), we see that the
central theme is basically ... nihilism. Is this a key? A crib?

While exploring some cryptography pages on Wikipedia for some other
challenges, I noticed something in the classical cryptography section:
[Nihilist cipher](https://en.wikipedia.org/wiki/Nihilist_cipher)! Sounds like
exactly what we need. I fumbled about a bit still trying to solve it like a
substitution cipher for some reason, but then I looked into how to break the
cipher properly. I plotted the frequency of each number in the cipher text:

          0   1    2    3    4    5    6    7    8    9  
        -----------------------------------------------  
   0   |  0   0    0    0    0    0    0    0    0    0  
   1   |  0   0    0    0    0    0    0    0    0    0  
   2   |  0   0    0    0    4    5   10    6    0    0  
   3   |  0   0    2    8   17    9    5    2    1    0  
   4   |  0   0    2    8   22   43   43   26    3    0  
   5   |  0   0    4   20   21   19   25   24   21   10  
   6   |  0   0    4    4   28   36   36   15   23    0  
   7   |  4   0    0    7   30   13   11   28    4    2  
   8   |  7   0    0   13    3    8   15   11    0    9  
   9   |  2   0    0    1    2    1    2    2    0    1

(Here I was trying to assign the 43 to the most common English letter, and so
on, but that is clearly not the right approach.)

It is notable that there are no low numbers, and it seems like the lower right
corner is actually a continuation (i.e. overflow). This all makes sense with
the nihilist cipher, which works like this:

1. a 5x5 polybius square is created based on a keyword - basically a substitution alphabet with 25 letters, where each letter in the cipher text is identified by its row and column in the square  
2. the plain text is encoded into numbers using the polybius square  
3. the key (another one) is also encoded into numbers using the polybius square  
4. the cipher text is created by taking each number from step 2 and adding it to a number from step 3, repeating the key numbers periodically as needed

There are some serious flaws in the cipher like this. In particular:

- a substitution cipher is trivially broken if we have enough data (the cipher text is quite long here), or we have cribs (we have that as well), or we know that the plain text is English (a fair assumption)  
- any of the numbers from steps 2 and 3 have to be valid polybius square coordinates, i.e. `1 ≤ row ≤ 5`, `1 ≤ column ≤ 5`, so `24` is a valid coordinate, while `30` is not

With this in mind, we can start breaking the cipher. The first step is to get
rid of the additive key. We can try to find out what the key length is before
doing anything else (see [SUCTF writeup -
cycle](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-26-SUCTF/README.md#465-misc
--cycle)), and this is what I did during the CTF. But as it turns out, it is
unnecessary.

The process is as follows:

- for each possible key length `Nk`, `1, 2, ...`  
  - put the cipher data into `Nk` columns  
  - for each column `i` (corresponding to a single key character)  
    - for each possible key character value `k[i]` that is a valid polybius coordinate `11, 12, 13, 14, 15, 21, ..., 55`  
      - subtract `k[i]` from all values in column `i`  
      - if they are all valid polybius coordinates, this is a possible value for `k[i]`  
  - if all `k[i]`s are valid, this is a valid key (and we can stop)

With a shorter cipher text, there might be some ambiguity with respect to key
selection. But basically, if the plain text for each column for a given key
length includes `11` and `55`, or `51` and `15`, i.e. opposite corners of the
original polybius square, then the key value we choose for that column is
unique, and any other key value would result in the plain text being outside
the polybius square.

Our cipher text is long enough and the shortest key we can find to uniquely
place all of the plain text within valid polybius coordinates is:

   21, 33, 45, 13, 42, 32, 33, 33

We don't know what this key is without breaking the polybius square, but we
will soon find out. After removing this additive key from the cipher text, we
are left with:

   12 41 52 31 41 34 32 12 34 14 54 22 41 35 22 13 44 35 32 14 34 34 44 44 13  
   14 25 14 35 12 31 13 44 13 21 13 33 15 35 41 52 35 14 11 22 54 42 31 13 44  
   14 11 54 41 45 34 32 25 31 12 15 35 41 52 32 31 14 51 13 21 13 13 35 41 45  
   12 11 32 23 13 12 31 13 34 14 12 44 32 53 24 41 44 35 32 35 13 54 13 14 44  
   11 32 14 34 14 33 11 41 14 34 13 34 21 13 44 41 24 34 41 44 42 31 13 45 11  
   22 44 13 52 14 35 23 22 14 35 31 13 33 42 54 41 45 24 32 35 23 14 33 33 14  
   21 41 45 12 31 32 11 52 31 13 44 13 14 21 41 45 12 11 32 52 41 45 33 23 33  
   32 15 13 12 41 24 41 44 25 13 12 14 21 41 45 12 12 31 32 11 31 41 44 44 32  
   21 33 13 52 41 44 33 23 14 35 23 21 13 14 21 33 13 12 41 25 13 12 21 14 22  
   15 12 41 12 31 13 34 14 12 44 32 53 11 41 12 31 14 12 32 22 14 35 13 35 32  
   41 54 12 31 13 44 13 11 12 41 24 34 54 33 32 24 13 32 35 12 31 32 11 14 34  
   14 55 32 35 25 52 41 44 33 23 32 33 41 35 25 12 41 13 35 32 41 54 14 25 14  
   32 35 12 31 13 44 13 33 14 53 32 35 25 14 35 23 33 13 11 11 11 12 44 13 11  
   11 24 45 33 33 32 24 13 12 31 14 12 12 31 13 34 14 12 44 32 53 42 44 41 51  
   32 23 13 11 14 35 23 14 33 33 12 31 41 11 13 33 32 12 12 33 13 33 45 53 45  
   44 32 13 11 12 31 14 12 11 32 34 42 33 54 23 41 35 41 12 13 53 32 11 12 32  
   35 12 31 13 44 13 14 33 52 41 44 33 23 14 35 54 34 41 44 13 32 24 54 41 45  
   14 44 13 52 32 33 33 32 35 25 12 41 35 13 25 41 12 32 14 12 13 42 33 13 14  
   11 13 33 13 14 51 13 14 35 41 12 13 52 32 12 31 12 31 13 12 32 34 13 14 35  
   23 42 33 14 22 13 12 41 31 41 33 23 11 45 22 31 14 34 13 13 12 32 35 25 32  
   35 11 32 23 13 14 35 13 35 51 13 33 41 42 13 33 14 21 13 33 33 13 23 11 22  
   12 24 53 12 31 13 34 14 12 44 32 53 22 14 35 21 13 34 41 44 13 44 13 14 33  
   12 31 14 35 12 31 32 11 52 41 44 33 23 53 41 35 12 31 13 22 44 41 11 11 52  
   14 54 21 13 12 52 13 13 35 12 31 13 52 14 21 14 11 31 14 35 23 13 44 32 13  
   14 12 11 13 51 13 35 41 22 33 41 22 15 32 35 12 31 13 14 24 12 13 44 35 41  
   41 35 32 14 34 14 35 53 32 41 45 11 33 54 52 14 32 12 32 35 25 24 41 44 54  
   41 45 44 42 44 41 34 42 12 44 13 42 33 54 54 41 45 44 11 12 44 45 33 54 34  
   44 44 13 14 25 14 35

(So now you can see all of the numbers are valid polybius coordinates.)

Despite using two-digit numbers, there are really only 25 unique values, so
this is a substitution cipher. The most common value in any text is generally
`0x20`, a space character. However, when using a polybius square, there are
only 25 characters to choose from, so the spaces are omitted, along with any
punctuation or indication of letter case. `I` and `J` are generally merged,
since the latter is quite rare in English text.

We can refer to a [frequency table like
this](http://sxlist.com/techref/method/compress/etxtfreq.htm) to gain a lot of
useful insight as to what we might expect to see in the plain text. In
particular, the letters appearing in the plain text will likely be
"ETAOINSH...", with the most frequent letter first. We will consider "THE" to
be a crib, and the most common trigram / three-letter sequence in the plain
text. With the crib only, we construct a temporary polybius square:

     a  T  E  d  e  
     f  g  h  i  k  
     H  m  n  o  p  
     q  r  s  t  u  
     v  w  x  y  z

This also has the advantage that many of the later letters might already be in
their correct position, as long as the keyword doesn't use them (this is why
"ZEBRA" shown as an example on the Wikipedia page for the nihilist cipher is a
good keyword). Then we deduce letters one at a time to make sense of the plain
text. At some point knowing the plot of The Matrix helps, and we can find the
relevant section in the film's script.

([full script with interactive decoding
here](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-31-SecurityFest/scripts/note/Decode.hx))

   --- Interactive decode mode ---  
   Current square:  
     a  T  E  d  e  
     f  g  h  i  k  
     H  m  n  o  p  
     q  r  s  t  u  
     v  w  x  y  z  
   Frequency chart:  
    33 61 82 62  5  
    14 14 18 12 13  
    33 50 41 23 46  
    55 11  0 43 17  
     5 16 10 17  1  
   Current plain text:  
TqwHqomTodygqpgEtpmdoottEdkdpTHEtEfEnepqwpdagyrHEtdayquomkHTepqwmHdvEfEEpquTamhETHEodTtmxiqtpmpEyEdtamdodnaqdoEofEtqioqtrHEuagtEwdphgdpHEnryquimphdnndfquTHmawHEtEdfquTamwqunhnmeETqiqtkETdfquTTHmaHqttmfnEwqtnhdphfEdfnETqkETfdgeTqTHEodTtmxaqTHdTmgdpEpmqyTHEtEaTqioynmiEmpTHmadodzmpkwqtnhmnqpkTqEpmqydkdmpTHEtEndxmpkdphnEaaaTtEaaiunnmiETHdTTHEodTtmxrtqvmhEadphdnnTHqaEnmTTnEnuxutmEaTHdTamornyhqpqTExmaTmpTHEtEdnwqtnhdpyoqtEmiyqudtEwmnnmpkTqpEkqTmdTErnEdaEnEdvEdpqTEwmTHTHETmoEdphrndgETqHqnhaugHdoEETmpkmpamhEdpEpvEnqrEndfEnnEhagTixTHEodTtmxgdpfEoqtEtEdnTHdpTHmawqtnhxqpTHEgtqaawdyfETwEEpTHEwdfdaHdphEtmEdTaEvEpqgnqgempTHEdiTEtpqqpmdodpxmquanywdmTmpkiqtyqutrtqorTtErnyyqutaTtunyottEdkdp  
   Replace: d  
   With:    a  
   Current square:  
     a  T  E  A  e  
     f  g  h  i  k  
     H  m  n  o  p  
     q  r  s  t  u  
     v  w  x  y  z  
   Frequency chart:  
    33 61 82 62  5  
    14 14 18 12 13  
    33 50 41 23 46  
    55 11  0 43 17  
     5 16 10 17  1  
   ...  
   ...  
   ...  
   Current square:  
     S  T  E  A  K  
     B  C  D  F  G  
     H  I  L  M  N  
     O  P  s  R  U  
     V  W  X  Y  z  
   Frequency chart:  
    33 61 82 62  5  
    14 14 18 12 13  
    33 50 41 23 46  
    55 11  0 43 17  
     5 16 10 17  1  
   Current plain text:  
TOWHOMITMAYCONCERNIAMMRREAGANTHEREBELKNOWNASCYPHERASYOUMIGHTKNOWIHAVEBEENOUTSIDETHEMATRIXFORNINEYEARSIAMALSOAMEMBEROFMORPHEUSCREWANDCANHELPYOUFINDALLABOUTHISWHEREABOUTSIWOULDLIKETOFORGETABOUTTHISHORRIBLEWORLDANDBEABLETOGETBACKTOTHEMATRIXSOTHATICANENIOYTHERESTOFMYLIFEINTHISAMAzINGWORLDILONGTOENIOYAGAINTHERELAXINGANDLESSSTRESSFULLIFETHATTHEMATRIXPROVIDESANDALLTHOSELITTLELUXURIESTHATSIMPLYDONOTEXISTINTHEREALWORLDANYMOREIFYOUAREWILLINGTONEGOTIATEPLEASELEAVEANOTEWITHTHETIMEANDPLACETOHOLDSUCHAMEETINGINSIDEANENVELOPELABELLEDSCTFXTHEMATRIXCANBEMOREREALTHANTHISWORLDXONTHECROSSWAYBETWEENTHEWABASHANDERIEATSEVENOCLOCKINTHEAFTERNOONIAMANXIOUSLYWAITINGFORYOURPROMPTREPLYYOURSTRULYMRREAGAN  
   Replace: z  
   With:    z  
   Current square:  
     S  T  E  A  K  
     B  C  D  F  G  
     H  I  L  M  N  
     O  P  s  R  U  
     V  W  X  Y  Z  
   Frequency chart:  
    33 61 82 62  5  
    14 14 18 12 13  
    33 50 41 23 46  
    55 11  0 43 17  
     5 16 10 17  1  
   Current plain text:  
TOWHOMITMAYCONCERNIAMMRREAGANTHEREBELKNOWNASCYPHERASYOUMIGHTKNOWIHAVEBEENOUTSIDETHEMATRIXFORNINEYEARSIAMALSOAMEMBEROFMORPHEUSCREWANDCANHELPYOUFINDALLABOUTHISWHEREABOUTSIWOULDLIKETOFORGETABOUTTHISHORRIBLEWORLDANDBEABLETOGETBACKTOTHEMATRIXSOTHATICANENIOYTHERESTOFMYLIFEINTHISAMAZINGWORLDILONGTOENIOYAGAINTHERELAXINGANDLESSSTRESSFULLIFETHATTHEMATRIXPROVIDESANDALLTHOSELITTLELUXURIESTHATSIMPLYDONOTEXISTINTHEREALWORLDANYMOREIFYOUAREWILLINGTONEGOTIATEPLEASELEAVEANOTEWITHTHETIMEANDPLACETOHOLDSUCHAMEETINGINSIDEANENVELOPELABELLEDSCTFXTHEMATRIXCANBEMOREREALTHANTHISWORLDXONTHECROSSWAYBETWEENTHEWABASHANDERIEATSEVENOCLOCKINTHEAFTERNOONIAMANXIOUSLYWAITINGFORYOURPROMPTREPLYYOURSTRULYMRREAGAN

The decoded plain text with whitespace and some punctuation inserted:

> TO WHOM IT MAY CONCERN,  
>  
> I AM MR. REAGAN, THE REBEL KNOWN AS CYPHER. AS YOU MIGHT KNOW, I HAVE BEEN
> OUTSIDE THE MATRIX FOR NINE YEARS. I AM ALSO A MEMBER OF MORPHEUS' CREW AND
> CAN HELP YOU FIND ALL ABOUT HIS WHEREABOUTS. I WOULD LIKE TO FORGET ABOUT
> THIS HORRIBLE WORLD AND BE ABLE TO GET BACK TO THE MATRIX SO THAT I CAN
> ENIOY THE REST OF MY LIFE IN THIS AMAZING WORLD. I LONG TO ENIOY AGAIN THE
> RELAXING AND LESS STRESS FUL LIFE THAT THE MATRIX PROVIDES AND ALL THOSE
> LITTLE LUXURIES THAT SIMPLY DO NOT EXIST IN THE REAL WORLD ANYMORE. IF YOU
> ARE WILLING TO NEGOTIATE, PLEASE LEAVE A NOTE WITH THE TIME AND PLACE TO
> HOLD SUCH A MEETING INSIDE AN ENVELOPE LABELLED:  
>  
> SCTFXTHEMATRIXCANBEMOREREALTHANTHISWORLDX  
>  
> ON THE CROSSWAY BETWEEN THE WABASH AND ERIE AT SEVEN O'CLOCK IN THE
> AFTERNOON. I AM ANXIOUSLY WAITING FOR YOUR PROMPT REPLY.  
>  
> YOURS TRULY,  
>  
> MR. REAGAN

(Note `ENIOY` spelled without the `J`.)

`sctf{THEMATRIXCANBEMOREREALTHANTHISWORLD}`

Original writeup
(https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-31-SecurityFest/README.md#485-crypto
--the-note).