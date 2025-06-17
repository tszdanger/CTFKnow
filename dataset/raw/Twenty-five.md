# Harekaze 2019 "Twenty-five" (100)

Writeup by Eric Zhang

## Description

With “ppencode”, you can write Perl code using only Perl reserved words.

- [twenty-five.zip](https://github.com/TeamHarekaze/HarekazeCTF2019-challenges/blob/master/twenty-five/attachments/twenty-five.zip)

## Solution

Looking at http://namazu.org/~takesako/ppencode/demo.html, we realize that the
flag is probably just obfuscated using the perl code, `crypto.txt`.

A quick look at `twenty-five.pl`, with modifications, reveals that it reads in
a file, replaces all letters with `*`'s, and then evals it. Here's an example
of a modification:

``` pl  
use open qw/:utf8/;

open(my $F, "<:utf8", 'crypto.txt') or die;  
my $text;  
while (my $l = <$F>)  
{  
 $l =~ s/[\r\n]+/ /g;  
 $text .= $l;  
}  
close($F);

#$text =~ y/abcdefghijklmnopqrstuvwxy/*************************/;

print($text);  
#eval($text);  
```

From here, it seems like we need to find the key to a simple substitution
(monoalphabetic replacement) cipher for `crypto.txt` and modify the `*`'s in
the code to convert it to working Perl.

Using the `reserved.txt` word bank, we can quickly solve this cipher using
letter combinations that seem unique. This is particularly effective in this
case because of 1) our ability to effectively filter through words via a
program and 2) because of the small size of the word bank.  
For example, we see that there is an `ejadp ejady` in `crypto.txt`. After
filtering our word bank to only five-letter words, we find that the only such
words with the first four letters matching are “untie” and “until”. This tells
us that `e` is replaced by `u`, `j` is replaced by `n`, `a` is replaced by
`t`, `d` is replaced by `i`, and `p` and `y` are either `e` or `l`.

By this method, filling in the letters we know, we find that the key is
`tbwiupohdnvrsyqlkmaxfjcge` (there are no `z`s, so there are only 25 letters
in the key.) We replace the `*`'s in `twenty-five.pl` with this key, run it
with `perl twenty-five.pl`, and get our flag,
`HarekazeCTF{en.wikipedia.org/wiki/Frequency_analysis}`.

Original writeup (https://github.com/swv-l/writeups/blob/master/2019-harekaze-
twenty-five.md).