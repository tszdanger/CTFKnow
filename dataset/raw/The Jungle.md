# The Jungle writeup (Challenge author perspective)

So this challenge turned out to be one of the most hated ones, and I'm sorry
about that, though some of the solvers said it was good in hindsight so that
may be because of people getting frustrated about the temple :P. Here was the
intended solution and the train of thought i thought people would take:

So of course when we press the link to go to the temple we get redirected a
lot, and since the path to the temple consists of 50 steps most browsers will
throw a "too many redirects" error. Chrome specifically throws it after 20
redirects and doesn't let you get to the temple. From here, one could write a
script to request all /path/1 - /path/50 requests in order to get to the
temple (or as i heard someone do, patch chrome to workaround the too many
redirects error XD). Many people got this far, though got stuck later as the
temple didn't actually give you anything and was a red herring. From here the
thought was that one would investigate some more into how the path system
worked. I released a patch that changed the cookie into a readable signed
cookie instead of an encrypted cookie to make this easier. Through
investigation one could for example find out that the system checked if the
path was correct after 50 steps, and if not sent you to /lost. Though the most
crucial thing to find out would be the timing of the requests. This challenge
was based on a side channel attack which isn't seen that often in ctfs. Here
comes the solution: there were two correct paths that one could take, one
leading to the temple and the other to the flag. the path to the temple
consisted of course of visiting /path/1 to /path/50 in order, with a redirect
to the temple at the end. The path to the flag however was random, consisting
still of 50 steps with integers from 1 to 50 but in a random order. The key to
figuring out the path to the flag was to notice that each correct step along a
path made the web server take 500 more ms to respond. For example, if you
cleared your session cookie to reset your path and then visited /path/1 the
request would take just over 500ms to return. If you instead requested
/path/2, the response would be nearly instant. Therefore, you could run
through all steps from /path/1 to /path/50 clearing your cookie in between and
notice that both /path/1 and /path/46 took unusually long to respond, and it
just so happens that the first step of the path to the flag is 46. You could
then save this cookie since it doesn't have anything uniquely identifying it
and use it to go through the 50 steps again to find the correct step 2. After
doing this 48 more times, you get redirected to the flag.

I think the most pms i got about the jungle were people being frustrated about
getting to the temple but not getting anything useful out of it. Some people
asked if there was stego involved on the images, but while there are some
really bad ctfs that would do that, we are not one of them. I think one of the
biggest problems was people not being familiar with this side channel attack,
or simply not testing it the way it was implemented. In hindsight this is
probably one of my most controversial challenges, requiring some mild
guesswork to get right, but still nothing absurdly unreasonable. I'm also
actually really split on if I'm actually sorry or not since one of the
problems was people not being familiar with the attack, which of course is one
of the points of ctfs. I hope you learned something :P

If you want to take a look at the challenge source, it's in the same folder as
this writeup file.  

Original writeup
(https://github.com/wat3vr/watevrCTF-2019/blob/master/challenges/web/jungle/writeup.md).