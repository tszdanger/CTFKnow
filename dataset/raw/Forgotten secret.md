# Forgotten secret

## Description

Last month we hired a new junior DevOps Enginner to migrate all our services
into containers. He was super hyped about Docker and in such a hurry, that he
forgot about best practices.  
You want to use one of our images? Sure, no problem. Just download image file,
run "docker load < image" and you are ready to go!

[image](image)

###### Hint -> Don't run it, try to inspect it!

## Solution

Let's extract all the file with `7zip`

Analyzing the file we find 3 interesting things  
1. `SECRET_KEY=58703273357638792F423F4528482B4D6251655468566D597133743677397A24` from the file `7dabd7d32d701c6380d8e9f053d83d050569b063fbcf7ebc65e69404bed867a5.json`  
2. `image\ee6ac2faa564229d89130079d3c24dcb016b6818c2a8f3901ad2a7de1fdb0faf\layer.tar\root\.ssh\id_rsa`

```  
-----BEGIN OPENSSH PRIVATE KEY-----  
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBge7WiWi  
2R3XsbedLz7zheAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDEGWD7vPEn  
jtMhLD7I370N/FuMBtcLSX1oCpwbqwGpOmmVMMtaLQmTq29pSrKax5+jMWvEZUxR+nJ0Hc  
gdyxsGPvP722WkfwMH+BOaq3hY8JQBuNqLWeq600N9erjVBk4e3JDQwKfbMTHYsZk8Qioq  
omuyrlF+SMGMzH+M5xsC80qTIlucXAW8ix8id+aflGZWKuQHmcS4m04JFhCCjWmuO3ES96  
R6oppvDtu1Lm/uQN/deBNMdzRrjiv/rHvN8sP+y7p2W/nfZMcArYJqGtbKlGaUWxZSBsmd  
IdHWa28BS0BrtU0a44bcHuIGhNK2dswhasZSkRqYVD5DQMQrsw6fOmV0/GC8QyEK5d45Tq  
EIoBVnbxYnFSJT6wdfDlMU3n+KF4nTOWL6AxhvmxAsn49cPn9IZoyCWVuICjQ6DXZQGw74  
4rFsazmrT+ZRX3/012a8nqf2k1PSWFFJq+F9D7d3Tdkx2r5SHAYZFH7cg96IdcRCEZoIoE  
Iziy1McKZLk9cAAAWAY+HzKDpq12FQ0QDSCXtt4XuqngE2ewe2o1KUFvcVD/nJZPnpf2Nq  
ea+s3SIFJ+hM1+Y+UAQTmFuiTa69yM45ZgkPrilKkHi5+nnNr/g70oSRBIsjwptpoDgSCL  
XCqBjvNWVm/I4FkekApDb2Z//ERh1xmfFvx3KDv4SQgfUP3q9PLbOziI3wGnjmqRczilS3  
6RHpNlJwbsCOuFgUkU7zymeBzU4OGcQ9Ls+Oh1X3xaAUPSnOqhoIZRiVrS48d38o6Y9j7I  
zyeiVKfTRJ7yCPmJf3KrB9u8j0DGlwzkep4OIGH/iQPHALFjfnkBYPEnC0gqRSS+y1/T2z  
aXGV1lsE3bh0fuk8Cja2XrB/RZftmBfHFT2YsKGeVlOlfUX0DlxyY06v3Zu8cS2/1QaHu7  
KMc2MfUc1WiDe6IzPM+/Pq5aS7IVztzMuIvNMCc2GPF2D3DtQnzmsVbddWa7OhQklhFrQo  
OXFEe0mgwUcl78FlLo0xmuOL2mrIfqWEcJ9GjY5ZiqKxWhfdXvXAyXlPzOFRJwX3k9jV5G  
0t2ZYVoFdovYL1bDxpOEqANLhxIFaYB/PbJQwiDWxNYrGyx2mbCcrMaikV1taBIjSy8qfL  
MPcRBqc2BUsdB8U33q7Ydj5V2nfm+3gUCH655KoQHMq9vOqmn/MciYtNbg9fDwYB4O38uD  
3iVSd3nEq4/TbNUlY1PoatM92Okkh0H/0CVirh6WIvrUu5dNnrj7ebY+QgQkPgKLyQYdNd  
HHEZi9RVBRHYbYbjJ4CRCBmAB1SCSS42roANni1O4k0sVNn5J66B0bOSktR7MFNJEV9C9y  
jVEPXQQD4CGDmRJZH+cnlVaJffw17ZkZZWSVeXfhnZOtus9V9gNLAE6M876AValfW6xKH9  
Iu03T5ihMHXbuSzPZG8Nc6WKq2+UGxh5S7UCAixbJQYzuC6A5HVrn9dcDlDbkYpY/DY5GZ  
BNrnUIJ1srWk0I10GbVUT+vrxGfa2UdEjZL8EWvsrFd0fKGClK0MYuTLwCAtrh0gerB7Rn  
YUh70cCCW5GR8XG8+VBqhyKq0SjaH5ppzTdPcAAkpHheKDkhXoWbP2Spi2HXl6/W6pro8l  
BoeZEAmEf2x+X4A+9Rg1Y74YkkjLNVbTfpuJRLwP0vR8ZOawispqmR7roirz6VnT7veeqo  
0ai8Ae5bTpinu75vTSteTjSeoKZmZEx5GhH+nFdL0CFwXoczPRRe7X7WjbrNxNs7EkYqD0  
HuI6QdWH/A46s768uqSoi0WpTU5q2eaE7U94xef4ndAMWUYeS4mVZYqiZsoJ85jgdGi56C  
ctdImSVihnmgS3NPgPxO1YQvueEZgCMNCYdf314FtXWXfGXP45c3CFZPq9KHdt+sWC0hDb  
+77SGlOIJOiVhguKwiw+WORRC87W7mVO1tUrK9JrPcXYMxV3Wpis6WKyYu2yWTvd2BAWRW  
djHRj+bdAYBSCuRCsoGkDt3BNO4+BTo/AcdGJ3QnJMB+qoUcaeg+LvUwv4jDhmRl5Mj4UE  
OphgXY+3oFbsyGrH4ArpZhp9KWbVY/kjl7juWOn14IiScVMSi+yiG5PkIaHfp9LRrGGy1e  
hyOv30gu2NYb30nwTrYo2jNFY2Txq9Ga7cMxWqpuwkSMUBsRx5LHMoZq0knjC4ghhY/Wbf  
OuxqRaGsGHe+J8kMOvbE7sdsLRGZgaxyWIGSiXozU0oqQWYYJcQ40jwscUHzJHli/G+U2R  
cwQpIlX4u8zjJzRSc7RxVe4/YxeEbPtdJCCi0gJCqLdpY/adJwgAm7fCaB3YZndD/bJBdj  
5mqRQPpED15FITyJ5LweORkItB+/KfsIHHCRtITVEH065o+aaCbIn17q3ToIExJujPVtTw  
vuYZEA==  
-----END OPENSSH PRIVATE KEY-----

```  
3. `cipher.bin` from `image\df6e2b0dba838bcc158171c209ae2c7b8aeec4a8638a2fa981abda520233a170\layer.tar\home\alice\cipher.bin`

Let's convert the `id_rsa` from `OPENSSH PRIVATE KEY` to `RSA PRIVATE KEY` (as
passphrase we can use the `SECRET_KEY`)

```console  
$ ssh-keygen -p -m PEM -f id_rsa  
Enter old passphrase:  
Key has comment 'root@kali'  
Enter new passphrase (empty for no passphrase):  
Enter same passphrase again:  
Your identification has been saved with the new passphrase.  
```

Now let's decrypt the `cipher.bin` using
[CyberChef](https://gchq.github.io/CyberChef/#recipe=RSA_Decrypt('-----
BEGIN%20RSA%20PRIVATE%20KEY-----%5CnMIIG4gIBAAKCAYEAxBlg%2B7zxJ47TISw%2ByN%2B9DfxbjAbXC0l9aAqcG6sBqTpplTDL%5CnWi0Jk6tvaUqymsefozFrxGVMUfpydB3IHcsbBj7z%2B9tlpH8DB/gTmqt4WPCUAbja%5Cni1nqutNDfXq41QZOHtyQ0MCn2zEx2LGZPEIqKqJrsq5RfkjBjMx/jOcbAvNKkyJb%5CnnFwFvIsfInfmn5RmVirkB5nEuJtOCRYQgo1prjtxEvekeqKabw7btS5v7kDf3XgT%5CnTHc0a44r/6x7zfLD/su6dlv532THAK2CahrWypRmlFsWUgbJnSHR1mtvAUtAa7VN%5CnGuOG3B7iBoTStnbMIWrGUpEamFQ%2BQ0DEK7MOnzpldPxgvEMhCuXeOU6hCKAVZ28W%5CnJxUiU%2BsHXw5TFN5/iheJ0zli%2BgMYb5sQLJ%2BPXD5/SGaMgllbiAo0Og12UBsO%2BOKx%5CnbGs5q0/mUV9/9NdmvJ6n9pNT0lhRSavhfQ%2B3d03ZMdq%2BUhwGGRR%2B3IPeiHXEQhGa%5CnCKBCM4stTHCmS5PXAgMBAAECggGAcEXfgwHQSEe7lZiRccy3nxRHDcq0wF%2BZD0JT%5Cn0nt7/fnVjXdcVgrHGubiaLQ9weRc/8BB5TXiFmV/tf9/HZ%2B1n0PXyPD6Js4ZXCyq%5CnfLmDs9g5xSqi5XnbrI9carEitcRgYccCmqJS%2BGoYEerMwvVW0wYfBzRKsDTTq9tB%5Cng9ilXHES116qeMEu/53fe4qOXftHBDqWR8vAF7nDWexqE3UHdpvNx4BFiXkjVkZ5%5CngChQKWa3RUOEORlex92kT0PftjAxCk2Cr2sQqHaVTG2xqITLHbJnSu/z62dR8BZh%5CnoUWeNzxY9RQOPCkrtGjAv7vW4wI0o%2BqxhYde/6Ttx28dnLrSFZZjOKiDUF9QPfMD%5Cn8uW8o5IOqEEicuMJkkUPYBggOHKux9imF8f6w1Jd5v/AfgjbrkHKcTGheQHUXWyQ%5CnhX2uGuNEtS0QK3p51yhiSF9gTRlwnH0I/u7DxYBs7cJ13YaTZUNOOD7HMN1icL%2Bx%5CnWnTjLwFxZOwLKGJX0mtd2VGrgr5hAoHBAOPDtvXd1Eoo0XR4ooDmqamVC7N22wB0%5CnIeoYJYGFfswyB3YDAPoV378ltl8VhTUqbYAl3aW0kaeal337qKXcPlRYtOel9fpn%5CnGfUFyU2gSHGNbDmI6fZNe/oEWRLR4TtVifKgYD/L9rMpFPjSymB1ZUeG1pysKjBR%5CnAGVNz5s1p/9Bk6/Tu2kggmqn2ZcQ3w5WBtVczCOUs3hf%2BCj7wVF24e39SzH0RG2V%5Cn7zbEQm10pe94NRHW0W11Of25u/l07Wbk/wKBwQDcaL0ZbmnJF3Wko3gtft%2BQxQcy%5CnOQuT%2Bensl3M286tD8Ng7YFIoa%2BYI3uG4Z9IlQM0BlRs3TQX%2BKpWIuDLe%2ByjEGn1Z%5CnAnGg41nc8D0NWKEXrOR3U3eGuL742elHV0FyI2AJBpo%2BD8/ybxSUXiSLmXUmYMm2%5CnjF4SiDQPgNhfmHQTTLuXwKsmoPx6UfAYPnDIozQPt9N5NcMoqw7eWTwaNbjJamcI%5CnGCYj3ImLeUDTnDiAuYxcf7giH7D/a3SmIKeMGSkCgcAHWbKW3rDSL90KmDYOWONS%5Cn0LeO9B//NMA/cMYNFwTPjDHHcjNe3sPYxFvNV8FzxMnB3/b2OQyWTxviefOoXqI4%5CnUKCN9UIp8ZfZ23Typ2CPIZRDixKZ20hL%2BkXxoIpXQtxv0xMoG%2Bn7QDEoEo1rbX52%5CnP3i/l6LI6mRL4KX5iVLBnxkoDHo42066KG6SPH4mVUplKliAMXVVRiuZDv7fJSoH%5CnZyw9EXf/3V3Z8519MM2GG%2BgCil853BWiBZN2anqa3nsCgcBgcOPtMMbQ2pb7Rxva%5CnrF0ed1fCvfs28G9OuqYLMWuK%2BuNid677SNsKnpudmK/25PfO7XNPK0CoCfIMNKzt%5CnrHAV/pFCVTNq9o/ngKb2JAW42knNfJQcOtI1CQRt1twoGRp4WI89AKY4qioTEW5k%5CnNu1vsYIRgjHXYgmFjxceHRMNLtIWgJNi/6X5z8iCky%2B%2BWsr45bJ%2BouuV6%2BNBn0IR%5CnJdiJKSmT/R0TK/hzMscO0JhYmtez0Z68L6m%2B2UHdPwSQ5KECgcBLzDzpSvuTaCz6%5Cn0lxDOMDjRA31nBRAUOuqo7dzCXeWKVoyOn0XJE63GZAZGDy6IMcrLRJo8Q9Z7Zo6%5CneXEmCKLkVYiSdY8iOXvFeJpi71mDtDuhL4lLwGopw%2BEup71H51ZxZBoqlhtNe52Z%5Cn0Eh%2BJp/s6Aj7FeHqqppPeXuymFapZ9av/IFm3WaBwfT7TQfFtBavl3wrSILl4yml%5CnfXNjHtn4yfHe80wRZtB4ZGR3SrgFo1Kum26rrvrEWAtJINKfigs%3D%5Cn
-----END%20RSA%20PRIVATE%20KEY-----','','RSAES-PKCS1-V1_5','SHA-1'))

#### **FLAG >>** `dctf{k33p_y0r_k3ys_s4f3}`  

Original writeup (https://github.com/K1nd4SUS/CTF-
Writeups/tree/main/dCTF_2021/Forgotten%20secret).