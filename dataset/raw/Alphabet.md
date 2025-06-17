# alphabet

## The task:

If you know your keyboard, you know the flag  
[submit_the_flag_that_is_here.7z](https://github.com/c00c00r00c00/writeups/raw/master/FireShell%20CTF%202019/alphabet/submit_the_flag_that_is_here.7z)

## solution  
Let's unarchive the file:  
```  
7z x submit_the_flag_that_is_here.7z  
```

We've got the `*.txt` file with the following content:

```  
$ head -c 234 submit_the_flag_that_is_here.txt  
72dfcfb0c470ac255cde83fb8fe38de8a128188e03ea5ba5b2a93adbea1062fa
65c74c15a686187bb6bbf9958f494fc6b80068034a659a9ad44991b08c58f2d2
454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1
3f79bb7b435b05321651daefd374cdc681dc06f  
```

By googling first 'word' we've got that it's sha256 of `L`:  
![gglit](https://github.com/c00c00r00c00/writeups/blob/master/FireShell%20CTF%202019/alphabet/google.png
"google it")

There are also 'words' by 32 chars length. By googling them we've got that
it's md5 of one of the ASCII's chars.

Okay, google, but we are too lazy to do it manualy.

Let's generate sha256 and md5 for alphabet and special chars:  
```  
use strict;  
use warnings;  
use feature 'say';  
use Digest::SHA qw(sha256_hex);  
use Digest::MD5 qw(md5_hex);

my $file = 'submit_the_flag_that_is_here.txt';  
open(my $fh, '<:encoding(UTF-8)', $file)  
 or die "Could not open file '$file' $!";

my $str;  
$str = <$fh>;  
chomp $str;

my @chars=("a".."z","A".."Z",0..9,qw(_ , . - { } [ ] ! @ # $ % ^ & * : ; '
"),"not found");

my %md5;  
my %sha256;

for(my $i=0; $i<=$#chars; $i++){  
 $md5{md5_hex($chars[$i])} = $i;  
 $sha256{sha256_hex($chars[$i])} = $i;  
}

for my $hash (split / /, $str) {  
 my $ind = -1;  
 $ind = $md5{$hash} if exists $md5{$hash};  
 $ind = $sha256{$hash} if exists $sha256{$hash};  
 my $res = $chars[$ind];  
 print $res;  
}  
```

By converting hashes into chars we've got the following text:  
```  
$ perl solution.pl | head -c 123

Lorem_ipsum_dolor_sit_amet,_consectetur_adipiscing_elit._Nunc_massa_risus,_bibendum_eu_urna_sit_amet,_venenatis_convallis_e  
```

It is dummy text of the printing and typesetting industry.

We know the format of flag so let's check this text for a flag:  
```  
$ perl solution.pl | perl -nE 'say $1 if /(F#{\w+})/'

F#{Y3aH_Y0u_kN0w_mD5_4Nd_Sh4256}  
```  

Original writeup
(https://github.com/c00c00r00c00/writeups/blob/master/FireShell%20CTF%202019/alphabet/alphabet.md).