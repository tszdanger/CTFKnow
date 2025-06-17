# DownUnder CTF 2023 Write-up: Excellent Vista!  

## Challenge Description  
What a nice spot to stop,lookout and watch time go by, EXAMINE the image and
discover where this was taken.  
NOTE: Flag is case-insensitive and requires placing inside DUCTF{} wrapper!
e.g DUCTF{Osint_Lookout}  
Author: Yo_Yo_Bro

The "Excellent Vista!" challenge in the DownUnder CTF 2023, categorized as an
OSINT (Open-Source Intelligence) challenge, presented participants with an
image named "ExcellentVista.jpg." The task was to examine the image and
determine the location where it was taken. The flag was to be wrapped in the
DUCTF{} format, such as DUCTF{Location_Name}.  

## How I Solved It  

Hey there, it's Dev_vj1 from Team_VALHALLA! Let me walk you through how I
tackled the "Excellent Vista!" challenge during the DownUnder CTF.  
Step 1: Downloading the Image

I started by downloading the image "ExcellentVista.jpg" from the provided
link.  
```  
https://play.duc.tf/files/79c7bcf86cf07a52fe4d46c20ed11fcb/ExcellentVista.jpg?token=eyJ1c2VyX2lkIjoxNTYyLCJ0ZWFtX2lkIjo4NjEsImZpbGVfaWQiOjEzNX0.ZPdCDw.fQDH7az4Sy8uSpNL5J6H_VgpOMU  
```  
  
Step 2: Exploring Exif Data

To extract valuable information from the image, I turned to its Exif data.
Exif data often contains metadata about the image, including details about
when and where it was taken.

To view the Exif data, I used a handy tool called exiftool. Here's the command
I used:  

`exiftool ExcellentVista.jpg`

Step 3: Examining the Exif Data

Upon running the exiftool command, I received an output that contained a
wealth of information.

```  
exiftool ExcellentVista.jpg  
ExifTool Version Number         : 12.49  
File Name                       : ExcellentVista.jpg  
Directory                       : .  
File Size                       : 2.7 MB  
File Modification Date/Time     : 2023:09:05 20:30:14+05:30  
File Access Date/Time           : 2023:09:05 20:30:13+05:30  
File Inode Change Date/Time     : 2023:09:05 20:30:14+05:30  
File Permissions                : -rw-r--r--  
File Type                       : JPEG  
File Type Extension             : jpg  
MIME Type                       : image/jpeg  
Exif Byte Order                 : Big-endian (Motorola, MM)  
X Resolution                    : 72  
Y Resolution                    : 72  
Resolution Unit                 : inches  
Y Cb Cr Positioning             : Centered  
Date/Time Original              : 2023:08:31 22:58:56  
Create Date                     : 2023:08:31 22:58:56  
Sub Sec Time Original           : 00  
Sub Sec Time Digitized          : 00  
GPS Version ID                  : 2.3.0.0  
GPS Latitude Ref                : South  
GPS Longitude Ref               : East  
GPS Altitude Ref                : Above Sea Level  
GPS Speed Ref                   : km/h  
GPS Speed                       : 0  
GPS Img Direction Ref           : True North  
GPS Img Direction               : 122.5013812  
GPS Dest Bearing Ref            : True North  
GPS Dest Bearing                : 122.5013812  
GPS Horizontal Positioning Error: 6.055886243 m  
Padding                         : (Binary data 2060 bytes, use -b option to
extract)  
About                           : uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b  
Image Width                     : 4032  
Image Height                    : 3024  
Encoding Process                : Baseline DCT, Huffman coding  
Bits Per Sample                 : 8  
Color Components                : 3  
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)  
Image Size                      : 4032x3024  
Megapixels                      : 12.2  
Create Date                     : 2023:08:31 22:58:56.00  
Date/Time Original              : 2023:08:31 22:58:56.00  
GPS Altitude                    : 70.5 m Above Sea Level  
GPS Latitude                    : 29 deg 30' 34.33" S  
GPS Longitude                   : 153 deg 21' 34.46" E  
GPS Position                    : 29 deg 30' 34.33" S, 153 deg 21' 34.46" E

```  

Among this information, one line in particular caught my attention:  
  
`GPS Position                    : 29 deg 30' 34.33" S, 153 deg 21' 34.46" E`  
  
This line revealed the GPS position of where the image was taken. The
coordinates were expressed in degrees, minutes, and seconds, with 'S'
indicating South   and'E'indicating East.  
  
Step 4: Converting Coordinates and Searching

To make sense of these coordinates, I first replaced "deg" with the degree
symbol "º". Then, I performed a simple Google search using the transformed
coordinates.  
`29º 30' 34.33" S, 153º 21' 34.46" E`

Google mape link:[
https://www.google.com/maps/place/29%C2%B030'34.3%22S+153%C2%B021'34.5%22E/@-29.5097263,153.3597801,19z/data=!4m4!3m3!8m2!3d-29.5095361!4d153.3595722?entry=ttu
](http://)

after zoom 2 times it's show The result of my search pointed me to a specific
location: Durrangan Lookout.  

Step 5: Forming the Flag

With the location identified, I formatted the flag in accordance with the
challenge requirements, placing it inside DUCTF{}:  

`Flag: DUCTF{Durrangan Lookout}`

And that's how I cracked the "Excellent Vista!" OSINT challenge! It was a fun
journey of examining Exif data, converting coordinates, and using online
resources to uncover the picturesque Durrangan Lookout.

This challenge reminded me of the power of Open-Source Intelligence and how it
can lead us to discover fascinating places and solve intriguing puzzles. Kudos
to the challenge author, Yo_Yo_Bro, for creating this enjoyable OSINT
challenge!

Original writeup (https://ctftime.org/team/241159).