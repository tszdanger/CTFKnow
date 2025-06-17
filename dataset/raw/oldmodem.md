# GACTF 2020 - Misc - oldmodem  
## Solver

Solved by luiscarloscb ( [looking for a team to
join](mailto:[email protected]), new to CTFs )

---

## Description

old modem (bell 202)

https://drive.google.com/drive/folders/1T94OrcveHAZTmTCwaVCojLXYlJc3lL3f?usp=sharing

---  
## Solution

Attached file was just named oldmodem, no extension.

Check possible headers with `binwalk`:

   /mnt/d/ctf/GACTF2020/modem$ binwalk oldmodem  
   DECIMAL       HEXADECIMAL     DESCRIPTION  
       --------------------------------------------------------------------------------  
   0             0x0             Zip archive data, at least v2.0 to extract,
compressed size: 28597, uncompressed size: 1938764, name: encoded  
   28739         0x7043          End of Zip archive

Use `unzip` to decompress the file:

   /mnt/d/ctf/GACTF2020/modem$ unzip oldmodem  
   Archive:  oldmodem  
   inflating: encoded

The new file, *encoded* also has no extension, so we try `binwalk` again.
Since there are no results here, we check the first bytes for magic numbers
with `xxd`.

   /mnt/d/ctf/GACTF2020/modem$ xxd encoded | head -n 5  
   00000000: 5249 4646 4495 1d00 5741 5645 666d 7420  RIFFD...WAVEfmt  
   00000010: 1000 0000 0100 0100 80bb 0000 0077 0100  .............w..  
   00000020: 0200 1000 6461 7461 2095 1d00 0000 f213  ....data .......  
   00000030: 9727 133a 4c4b 825a 8167 1072 b879 6f7e  .'.:LK.Z.g.r.yo~  
   00000040: ff7f 6f7e b879 1072 8167 825a 4c4b 133a  ..o~.y.r.g.ZLK.:  
  
The first bytes tell us that the file is a WAV file, in a RIFF container
(https://en.wikipedia.org/wiki/Resource_Interchange_File_Format).

We add the wav extension and play the file, the sounds are indeed modem-like,
so the flag is probably saved as audio modem tones, this also explains why the
problem description specified the Bell 202 modem.

The fastest way to extract the data from the audio is to use
[minimodem](http://www.whence.com/minimodem/)

By checking minimodem's man page, we can find the options we need,
specifically:

* `-r` to specify that we are on receive or read mode (as opposed to generating the audio tone)  
* `-f` to select the file to read from  
* `1200` as baud mode, since the Bell202 modem had 1200 bps transmission.

Putting everything together, we just run `minimodem` with the appropriate
options:

   /mnt/d/ctf/GACTF2020/modem$ minimodem -r -f encoded 1200  
   ### CARRIER 1200 @ 1200.0 Hz ###  
   The Bell 202 modem was an early (1976) modem standard developed by the Bell
System. It specifies audio frequency-shift keying (AFSK) to encode and
transfer data at a rate of 1200 bits per second, half-duplex (i.e.
transmission only in one direction at a time). These signalling protocols,
also used in third-party modems, are referred to generically as Bell 202
modulation, and any device employing it as Bell-202-compatible.  
  
   Bell 202 AFSK uses a 1200 Hz tone for mark (typically a binary 1) and 2200
Hz for space (typically a binary 0).  
   In North America, Bell 202 AFSK modulation is used to transmit Caller ID
information over POTS lines in the public telephone network. It is also
employed in some commercial settings.  
  
   In addition, Bell 202 is the basis for the most commonly used physical
layer for the HART Communication Protocol - a communication protocol widely
used in the process industries.  
  
   Surplus Bell 202 modems were used by amateur radio operators to construct
the first packet radio stations, despite its low signalling speed. A modified
Bell 202 AFSK modulation, a common physical layer for  
   AX.25, remains the standard for amateur VHF operation in most areas.
Notably, Automatic Packet Reporting System (APRS) transmissions are encoded
this way on VHF. On HF, APRS uses Bell 103 modulation.  
  
   The Bell 202 standard was adopted around 1980 as the communications
standard for subsea oil and gas production control systems, pioneered by the
then FSSL (Ferranti Subsea Systems Ltd.) Controls, a spin-out company from the
former TRW - Ferranti joint venture in the UK. This modulation standard was
retained until around 2000, when it was superseded by faster FSK and PSK
modulation methods, although it is still utilised for extension of existing
control systems that are already configured for this technique.  
  
   The 202 standard permitted useful techniques such as multi-dropping of
slave modems to allow multiple nodes to be connected to the host via a single
modem channel. Other techniques have included superposition of signal on power
conductors, and distances in excess of 80 km were achieved in subsea
applications using these techniques. This has been enhanced through the use of
Manchester encoding over the FSK link, to provide simple Modulo-2 RZ (return
to Zero) bit error detection and suppression improvement over these long
distances.  
  
   Here is the flag: GACTF{9621827f-a41b-4f27-8d72-9e0b77415a4f}  
   ### NOCARRIER ndata=2423 confidence=4.397 ampl=0.997 bps=1200.00 (rate
perfect) ###

The final step is to input the flag and we're done!.

Original writeup
(https://gist.github.com/luiscarloscb/8dad42c3bd66f1d885e435869926d42b).