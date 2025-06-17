## Chaplin's PR Nightmare - 1  
### Description  
```  
Charlie Chaplin has gotten into software development, coding, and the like...  
He made a company, but it recently came under fire for a PR disaster.  
He got all over the internet before he realized the company's mistake,  
and is now scrambling to clean up his mess, but it may be too late!!  
Find his Twitter Account and investigate! NOTE THAT THESE CHALLENGES DO NOT  
HAVE DO BE DONE IN ORDER!

The inner content of this flag begins with "pe"

author: Thomas  
```

-----

### Writeup  
Starting off with the first challenge, we are given a few key pieces of
information. First of all, a full name. Next we also have key words such as
coding, Software development etc.. These are good to use to modify search
parameters to vary a search until the desired result is found.

Thankfully, since they've given us information, and a platform to look on,
this should be pretty straight forward. Going to Twitter, we can use the
search function and start plugging in the combinations we have. One thing with
Twitter searches and other search engines in general, is to sort by the type
of content you're looking for to begin with. For this challenege, that would
be a profile, instead of a specific tweet or hashtag or trending topic.

![image1](https://raw.githubusercontent.com/BYU-CTF-
group/writeups/main/UIUCTF_2021/OSINT_Charlie/twitter.JPG)

So as the above image shows, "charlie chaplin coding" brings up a solitary
account - this looks like it. Further investigation leads to a few couple
things. First off, there's a YouTube link, which will lead us straight to the
next challenge. After looking at a few of the tweets, we can see that he has
one thread dedicated to "lists". Any Twitter user who's used it for long
enough will know that Twitter users have the abillity to create their own
"lists", mostly containing users they select for some reason.

![image2](https://raw.githubusercontent.com/BYU-CTF-
group/writeups/main/UIUCTF_2021/OSINT_Charlie/twitter-hint1.JPG)

To access a user's lists, one clicks on the options button on their profile,
which then opens a drop down menu with the "View Lists" option.

![image3](https://raw.githubusercontent.com/BYU-CTF-
group/writeups/main/UIUCTF_2021/OSINT_Charlie/twitter-hint2.JPG)

Now once we open that we are rewarded with a flag right away. Not too bad, but
definitely a good place to hide a flag! A common trend among these challenges
is that they show off side features of platforms that require a step or two to
discover.

![image4](https://raw.githubusercontent.com/BYU-CTF-
group/writeups/main/UIUCTF_2021/OSINT_Charlie/flag-twitter.JPG)

**Flag:** `uiuctf{pe@k_c0medy!}`

-----

### Real-World Application  
When it comes to initial OSINT Challenges and search engines, it helps to
utilize a bit of google-fu like skills. Search engines such as Twitter's often
include additional filters that can be used to parse through less relevant
results. Next, identifying key words to utilize in search parameters and then
testing a combination of such parameters will allow for the search to be more
accurate and thorough. These combined with other strategies such as including
the '@' character or ommitting words or requiring words lead to more optimal
searching, which is a necessary tool for cybersecurity.  

Original writeup (https://github.com/BYU-CTF-group/writeups-
uiuctf/blob/main/OSINT_Charlie/README.md).