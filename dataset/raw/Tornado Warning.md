## Challenge Description

_Check out this alert that I received on a weather radio. Somebody transmitted
a secret message via errors in the header! Fortunately, my radio corrected the
errors and recovered the original data. But can you find out what the secret
message says?_

Note: flag is not case sensitive.  
Author: Pomona  
Hints:  
> The header is encoded with Specific Area Message Encoding.

> The three buzzes are supposed to be identical, but in this challenge, they
> are different due to errors.

## Intuition

Even without the hints, it's pretty easy to find out about
[SAME](https://en.wikipedia.org/wiki/Specific_Area_Message_Encoding). As it
usually goes with this challenges, all that's left to do is find a tool that
can interpret the given `.wav` file.

## Solution

We found  
[this](https://forums.radioreference.com/threads/same-
decoding.271140/#post-2210417)  
thread from 2013 talking precisely about what we're interested in. Using  
[seatty](https://www.dxsoft.com/en/products/seatty/) with the **same**
setting, we got 3 messages. For each position there were two ASCII options to
chose from. One of them appeared once and the other twice. By choosing the
characters that appeared once, we obtained the flag.

### Flag

`uiuctf{.hidden_likes_chilly_weather}`  

Original writeup (https://dothidden.xyz/uiuctf_2023/tornado_warning/).