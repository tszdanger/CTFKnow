## Zip Madness  
![date](https://img.shields.io/badge/date-11.03.2020-brightgreen.svg)
![General category](https://img.shields.io/badge/Category-General-
lightgrey.svg) ![score](https://img.shields.io/badge/score-175-blue.svg)

### Description  
```  
Evan is playing Among Us and just saw an imposter vent in front of him! Help
him get to the emergency button by following the directions at each level.  
```

### Attached files  
- flag.zip

### Solution  
The whole gist of this challenge is:  
1. Unzip file  
2. Read direction.txt (Either says left or right)  
3. Unzip the corresponding side (There are 2 files <number>left.zip or <number>right.zip)  
 a. The number starts from 1000 down to 1 which is where the flag is  
4. Repeat the process over and over again until you reach 1

This requires some scripting knowledge which I previously didn't have. I chose
to learn a little bit of bash scripting so I formulated this script:  
```  
#!/bin/bash

unzip flag.zip  
for ((direct=1000; direct>=1; direct--))  
do  
       read -r side < direction.txt  
       unzip -o "$direct$side.zip"  
done  
```  
So basically, what this script does is:  
1. Initially unzip the flag.zip file  
2. Loop from 1000 to 1 decrementing  
3. While going down the numbers, read the direction.txt file  
 a. Assign it a value "side"  
4. unzip the zipped file based on its "side" and "direct"  
 a. The "-o" is to overwrite the direction.txt file so I won't have to type
"y" all the time to overwrite it  
5. Repeat

After running that command, it unzipped EVERYTHING all the way until the flag
was found! (flag.txt)  
This was my first time trying bash scripting so it took a lot of debugging and
googling to solve this problem.

### Flag  
```  
nactf{1_h0pe_y0u_d1dnt_d0_th4t_by_h4nd_87ce45b0}  
```

Original writeup (https://github.com/JoshuEo/CTFs/edit/master/NACTF_2020).