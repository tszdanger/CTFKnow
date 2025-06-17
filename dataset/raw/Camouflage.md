We were given a file called Camouflage-sound.wav and the problem text was the
following:

```General: We've got the hideouts. From here on out, hear out!  
You: Roger!  
Hint 1: steganography  
Hint 2: No passwords are involved  
Hint 3: Camouflage is the challenge name. Not associated to tool  
```

A quick google search for audio steganography tools gives Steghide as
basically the first result. Using the command `steghide info Camouflage-
sound.wav` we can find that the file contains a hidden file, which steghide
can find. It can be extracted with the command `steghide extract -sf
Camouflage-sound.wav` and the name of the extracted file is vbs.bmp. Using the
same commands on the new file, we can get another file called inf.txt, which
contains the following text:

```  
Sampling Rate : 44100  
Bands Per Octave : 24  
pps : 32  
min freq : 20 Hz  
Bits per sample : 32  
```

This info can be used with a tool called ARSS on the bitmap image vbs.bmp we
found earlier to create a .wav audio file. In the audio file, a voice is
saying the following:

```  
The flag is
6461726b434f4e7b6c6f6f6b355f6c316b335f7930755f643135633076337233645f345f703163747572317a33645f37306e335f7d.  
```

Interpreting the hex as ascii, we get the flag
**darkCON{look5_l1k3_y0u_d15c0v3r3d_4_p1ctur1z3d_70n3_}**.

The tools used:  
  
http://steghide.sourceforge.net/  
  
http://arss.sourceforge.net/

Original writeup (https://github.com/keyboard-monkeys/ctf-
writeups/blob/main/2021-darkctf/misc_camouflage.md).