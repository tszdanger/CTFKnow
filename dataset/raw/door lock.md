Challenge_Name = Door Lock  
Description = The door is open to all! See who is behind the admin door??  
Author = r3curs1v3_pr0xy  
Challenge_Link = http://34.135.171.18/

# Solution_Explain  
When we go to website, It was same website with the first challenge. Cool,
Right?  
So, i go to login page and trying sql payloads.

# Sql Payload Worked! (but not get flag)  
Payload = admin' or '1'='1

# Notice Parameter (?id=123)  
So I have been crazy because sql injection not worked.  
But i noticed the (id) parameter and (values).

# Final Soultion (IDOR)  
So I used Burpsuite to bruteforce the (Values) in the (?id=) parameter.  And
Burp show me the values (1766).  
So I paste the that value(1766) in the (?id=) parameter.  Yessssssssssssssss!  
 We got flag.

Get_Flag_Url = http://34.135.171.18/profile/index.php?id=1766

# Flag: GrabCON{E4sy_1D0R_}

# Note: I can't show picture and images to explain because of my pc.(Sorry)  

Original writeup
(https://github.com/ComdeyOverFlow/CyberGrabsCTF2021/blob/main/Door_Lock.md).