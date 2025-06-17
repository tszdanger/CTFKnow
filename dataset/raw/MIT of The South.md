## MIT of the South

### Category  
Web

### Points  
150

### Description  
Welcome to UTD! We like to call ourselves the MIT of the South (not really).
The flag for this challenge is hidden in one of the classrooms, can you find
it?

### Solution  
The challenge's landing page is at
`http://18.216.238.24:1004/webpage/files/dir/index.html`.

If we look at robots.txt, which typically hold a list of locations that web
crawlers are allowed or disallowed to visit, we get the message:  
```  
Robots!?  
There are no robots here!  
Only Temoc, and his army of tobors!!  
```  
(robots.txt is located at
`http://18.216.238.24:1004/webpage/files/dir/robots.txt`)

There are no robots, only tobors. So we need to go to tobors.txt at
`http://18.216.238.24:1004/webpage/files/dir/tobors.txt`, where we get a list
of locations to visit  
```  
/ad/  
/ad/1.100/  
/ad/1.101/  
/ad/1.102/  
/ad/1.103/  
...  
```

Using a webcrawler that checks every location until the string `texsaw` is
found in the returned html document, we find that the classroom `/ecss/4.910/`
contains the flag, which is ` texsaw{woo0OOo0oOo00o0OOOo0ooo0o00Osh}`.

(this is at `http://18.216.238.24:1004/webpage/files/dir/ecss/4.910/`)

### Flag  
` texsaw{woo0OOo0oOo00o0OOOo0ooo0o00Osh}`