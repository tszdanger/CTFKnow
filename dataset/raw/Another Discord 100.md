# Misc: Another Discord

## Task:  
```  
Author: daffainfo

TCP1P has another discord server?  
https://discord.gg/kzrryCUutP  
```

## Solution:

You are given a discord server, upon joining, you see two channels. A text
channel, and a voice channel.

The thing that sticks out the most is the fact that there is an event going
on. Just click on `Event Details` and you should see a flag there. This
implies that the challenge requires you to go through some discord stuff to
find the code. Anyways, we have part 3.

```  
Part 3: 45_r341ly  
```

Next part is just like other discord challenges typically present in CTF. You
have to either search for the channels, the roles, or both. Let's start with
the roles.

You can use this curl command to get all the roles in a server:

```  
curl -sH "AUTHORIZATION: (discord token here)"
https://discordapp.com/api/v6/guilds/{guild.id}/roles  
```

I don't need to write about getting your discord token, since there's 2000
guides out there. Just know that you shouldn't share it with anyone. Anyways,
running this will result in this role showing up inside the list:

```  
...  
"name":"Part 2: d0cUM3n74710n_W"  
```

Cool, let's do the same with channels

```  
curl -sH "AUTHORIZATION: (discord token here)"
https://discordapp.com/api/v6/guilds/{guild.id}/channels  
```

And then, we get:

```  
...  
"name":"Part 4: _H31pFu1}  
```

So, now we have:

```  
d0cUM3n74710n_W45_r341ly_H31pFu1}  
```

But where's Part 1?  
Well, recently, Discord added a new thing that is rarely used, called the text
channels inside voice channels, or something like that. When you hover over a
voice channel, there's the new text icon that pops up, click it, then you will
see the flag.

```  
Part 1: TCP1P{d15c0RD_  
```

So the full flag is

## Flag:

```  
TCP1P{d15c0RD_d0cUM3n74710n_W45_r341ly_H31pFu1}  
```

## Resources

[Discord Developer Guide](https://discord.com/developers/docs/resources/guild)