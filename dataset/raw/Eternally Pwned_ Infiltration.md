## Eternally Pwned: Infiltration  
- Tags: Forensics  
- Description: I recently had my passwords and other sensitive data leaked, but I have no idea how. Can you figure out how the attacker got in to my PC?

## Solution  
- To solve this question you need to download the following file and open it using Wireshark tool, to intercept all of the traffic.  
- There we will see a lot of logs, after searching for something that will look suspicious, we find one of the Echo requests.

![first-part-flag.png](https://github.com/archv1le/CTF-Write-
Ups/assets/158765690/efb98506-465c-49e7-a6c9-59b440c0c1c7)

- In there we will see some interesting Base64 stringm when we decode it, we get:

```  
wctf{l3tS_  
```

- This is the first part of the flag, now let's find another two, using the search bar and look for more of those strings, that will give us the final result with the flag.

![second-part-flag.png](https://github.com/archv1le/CTF-Write-
Ups/assets/158765690/26fc79f1-b303-4852-8f71-c09124f087dd)

```  
3teRn4lLy_g0_  
```

![third-part-flag.png](https://github.com/archv1le/CTF-Write-
Ups/assets/158765690/e471a28f-4c30-498e-889f-be7af415963b)

```  
bLU3_7n9wm4iWnL}  
```

- Let's concatenate those parts into one to get the final result.

```  
wctf{l3tS_3teRn4lLy_g0_bLU3_7n9wm4iWnL}  
```

Original writeup (https://github.com/archv1le/CTF-Write-
Ups/blob/main/WolvCTF%202024/Eternally%20Pwned%3A%20Infiltration/Solution.md).