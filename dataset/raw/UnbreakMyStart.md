**Description**

> https://www.youtube.com/watch?v=p2Rch6WvPJE

**Files provided**

- [`unbreak_my_start.tar.xz`](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-10-05-Hackover-CTF/files/unbreak_my_start.tar.xz)

**Solution**

   $ xxd unbreak_my_start.tar.xz  
   0000000: 504b 0304 1400 0800 0800 04e6 d6b4 4602  PK............F.  
   0000010: 0021 0116 0000 0074 2fe5 a3e0 07ff 007d  .!.....t/......}  
   0000020: 5d00 331b 0847 5472 2320 a8d7 45d4 9ae8  ].3..GTr# ..E...  
   0000030: 3a57 139f 493f c634 8905 8c4f 0bc6 3b67  :W..I?.4...O..;g  
   0000040: 7028 1a35 f195 abb0 2e26 666d 8c92 da43  p(.5.....&fm...C  
   0000050: 11e1 10ac 4496 e2ed 36cf 9c99 afe6 5a8e  ....D...6.....Z.  
   0000060: 311e cb99 f4be 6dca 943c 4410 8873 428a  1.....m..<D..sB.  
   0000070: 7c17 f47a d17d 7808 b7e4 22b8 ec19 9275  |..z.}x..."....u  
   0000080: 5073 0c34 5f9e 14ac 1986 d378 7b79 9f87  Ps.4_......x{y..  
   0000090: 0623 7369 4372 19da 6e33 0217 7f8d 0000  .#siCr..n3......  
   00000a0: 0000 001c 0f1d febd b436 8c00 0199 0180  .........6......  
   00000b0: 1000 00ad af23 35b1 c467 fb02 0000 0000  .....#5..g......  
   00000c0: 0459 5a                                  .YZ

We can see in the hexdump that the file ends in `YZ`, the normal footer for
`xz` archives, but the header is `PK`, as seen in `zip` archives. Since the
challenge says to unbreak its start, we can only assume that this should be a
valid `xz` file, so the beginning is wrong.

First of all, we should find a specification for the format. Luckily, `xz` is
[well documented](https://tukaani.org/xz/xz-file-format-1.0.4.txt). The
relevant sections are the `2.1.1. Stream Header` and `2.1.2. Stream Footer`.

The header should be:

- Magic bytes - `0xFD, "7xXZ", 0x00`  
- Stream flags - should be identical to the flags in the footer, i.e. `0x00 0x04`  
- [CRC32](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) - calculated from the Stream flags only, `0xE6 0xD6 0xB4 0x46`

To calculate the CRC32 in the terminal (then change endianness of result):

   $ (printf "obase=16;ibase=10;"; printf "\x00\x04" | cksum -o 3 | cut -d " " -f 1) | bc  
   46B4D6E6

As it turns out, the correct CRC32 is already in the file, at offset `0x0B`.
Let's try to replace the first 11 bytes of the file with our constructed
header:

   $ dd if=unbreak_my_start.tar.xz of=trimmed.bin bs=1 skip=11  
   184+0 records in  
   184+0 records out  
   184 bytes transferred in 0.000920 secs (199988 bytes/sec)  
   $ (printf "\xFD7zXZ\x00\x00\x04"; cat trimmed.bin) > fixed.tar.xz  
   $ xz -d fixed.tar.xz  
   $ tar zxvf fixed.tar  
   x flag.txt

`hackover18{U_f0und_th3_B3st_V3rs10n}`

Original writeup
(https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-10-05-Hackover-
CTF/README.md#337-forensics--unbreakmystart).