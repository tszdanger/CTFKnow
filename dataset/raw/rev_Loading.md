# rev/Loading (81 solves/134 points)  
## Description:  
This program takes an awful amount of time to generate the flag, I wonder if
there’s any other way to get it…  
A binary.

##Solution:  
Decompile in ghidra like usual. We see that it loops through the main loop a
lot of time we can probably simplify that. Since we know that the only
important part is the first line in the while loop we can delete everything
else. So the total number of iterations we possibly need is `0x39*0xab` (also
known as the LCM). That's `9747`. So the only code that really matters now is:  
```  
long big_counter;  
big_counter = 0;  
while (big_counter < 9747) {  
	flag[big_counter % 0x39] = flag[big_counter % 0x39] ^ orz[big_counter % 0xab];  
}  
```  
When we read out the data segment of flag, we get an uninitialized `{48, 2, 4,
2, 28, 92, 86, 87, 93, 99, 31, 93, 65, 28, 88, 91, 79, 38, 84, 91, 20, 84,
110, 104, 37, 127, 9, 66, 81, 1, 44, 59, 13, 67, 84, 58, 82, 19, 84, 112, 81,
80, 46, 86, 28, 15, 102, 20, 6, 103, 94, 19, 60, 69, 73, 49, 2}`.  
Now we just need this "orz" string/list. If we check strings we can find it.  
`Never gonna give you up Never gonna let you down Never gonna run around and
desert you Never gonna make you cry Never gonna say goodbye Never gonna tell a
lie and hurt you`  
This was a very big bruh moment.  
Parsing it out we get the total code:  
```  
#include <stdio.h>  
int main(void) {  
	long big_counter; char flag[57];  
	char flag[57] = {48, 2, 4, 2, 28, 92, 86, 87, 93, 99, 31, 93, 65, 28, 88, 91, 79, 38, 84, 91, 20, 84, 110, 104, 37, 127, 9, 66, 81, 1, 44, 59, 13, 67, 84, 58, 82, 19, 84, 112, 81, 80, 46, 86, 28, 15, 102, 20, 6, 103, 94, 19, 60, 69, 73, 49, 2}  
	char orz[172] = {'N', 'e', 'v', 'e', 'r', ' ', 'g', 'o', 'n', 'n', 'a', ' ', 'g', 'i', 'v', 'e', ' ', 'y', 'o', 'u', ' ', 'u', 'p', ' ', 'N', 'e', 'v', 'e', 'r', ' ', 'g', 'o', 'n', 'n', 'a', ' ', 'l', 'e', 't', ' ', 'y', 'o', 'u', ' ', 'd', 'o', 'w', 'n', ' ', 'N', 'e', 'v', 'e', 'r', ' ', 'g', 'o', 'n', 'n', 'a', ' ', 'r', 'u', 'n', ' ', 'a', 'r', 'o', 'u', 'n', 'd', ' ', 'a', 'n', 'd', ' ', 'd', 'e', 's', 'e', 'r', 't', ' ', 'y', 'o', 'u', ' ', 'N', 'e', 'v', 'e', 'r', ' ', 'g', 'o', 'n', 'n', 'a', ' ', 'm', 'a', 'k', 'e', ' ', 'y', 'o', 'u', ' ', 'c', 'r', 'y', ' ', 'N', 'e', 'v', 'e', 'r', ' ', 'g', 'o', 'n', 'n', 'a', ' ', 's', 'a', 'y', ' ', 'g', 'o', 'o', 'd', 'b', 'y', 'e', ' ', 'N', 'e', 'v', 'e', 'r', ' ', 'g', 'o', 'n', 'n', 'a', ' ', 't', 'e', 'l', 'l', ' ', 'a', ' ', 'l', 'i', 'e', ' ', 'a', 'n', 'd', ' ', 'h', 'u', 'r', 't', ' ', 'y', 'o', 'u','\0'};  
	big_counter = 0;  
	while (big_counter < 9747) {  
	flag[big_counter % 0x39] ^= orz[big_counter % 0xab];  
	big_counter = big_counter + 1;  
	}   
	printf("%s\n",flag);  
	return 0;  
}  
```  
Compile and run this and we get:  
flag{f1v3_bi11i0n_y34r5_i_th1nk_th3_5un_is_r3d_gi4nt_n0w}

## Flag:  
flag{f1v3_bi11i0n_y34r5_i_th1nk_th3_5un_is_r3d_gi4nt_n0w}

Original writeup (https://github.com/idekctf/litctf-
writeups/blob/main/loading.md).