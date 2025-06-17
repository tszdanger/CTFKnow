# Real EC

## Task

We use the elliptic curve P256 (NIST-standard).  
The programme generates some random 1000-Byte secret (from urandom).  
This is split into 250 32-bit Integers *e_i*.  
Then for all 250 parts, we also generate some random *n = x0...0x0...0x* (8
bit unknown).  
Finally, we get *g^(e_i * n)*.

Find the hash of the secret, you have 100 seconds.

## Solution

* We cannot break ECDSA.  
* Each point has 40 Bit -> somehow brute-force

Before we get the 250 values, we have arbitrary time.  
Create a lookup table, then just search for all of these points in table.

Table gets too large (some TB RAM), instead meet-in-the-middle.  
* Create k bit table.  
* Try 40-k bit in-time

In the end the following worked  
* Use server, with 80 cores to lookup points in parallel  
* Use 22 Bit table  
* Compute inverses of possible n before  
* try to use addition of points (instead of multiplication) for speedup

Finished Lookup table: 162.18 seconds  
Finished with all points: 41.88 seconds  

Original writeup
(https://github.com/ENOFLAG/writeups/tree/master/pwn2win/real_ec).