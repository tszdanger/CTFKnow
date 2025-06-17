*For the full experience with images see the original blog post!*

This challenge was released with the final batch of challenges of the
qualifiers, 6 hours before end.  
Some of our team (including, but not limited to, me) had already worked pretty
much through the night,  
but we anticipated the challenges eagerly.  
Thankfully, we managed to get the first and only solve for this challenge with
great team work.

The challenge provides us with a .NET Core C# binary (for example see all the
.NET symbols with `strings`).  
With luck, you can decompile such binaries with tools like dotPeek or ILSpy.  
[Liam](https://wachter-space.de) quickly realized this and exported an archive
of C# files from dotPeek for us.

Interacting a bit with the program (you can connect to a local instance at
port 3284) we can generate a session ticket and are then greeted by the
system:

> Welcome to Campbell Airstrip, Anchorage.  
>  
> Runway 1 is available. Please provide a callsign:

With the challenge description I already found a reference to the name
[PCaS](https://en.wikipedia.org/wiki/Portable_collision_avoidance_system),  
setting the theme for the challenge.  
Specifically, the challenge is implemented as a kind of airport controller,
processing planes from loading to takeoff.

Looking at `AirportSession.cs`, we find that we (sadly) get the flag as an
apology if all runways are blocked with crashed airplanes.  
The `AirportSession` is a big state machine handling the flow of processing a
plane (see diagram).

AirportSession processing state machine

The processing contains some important information:

- Callsigns must match the regex `r"^[A-Z]{3}[A-Z0-9]{1,}$"`  
- Plane data contains runway, number of containers & max takeoff weight  
- We need to provide a minimum of `NumberOfContainers / 2`, to stay economical of course  
- Loading can run into a timeout  
- There is a crash check at takeoff

LoadPlane function in Airport

The most important logic is implemented in `Aiport.cs` though.  
When loading a plane, the `LoadPlane` method starts a worker thread and
weights for a signal before retrieving and returning the result.  
The method `DoWork` tries to get the optimal loading configuration with a
branch and bound knapsack solver and is cancelled after 15 seconds.  
Sadly, the `Solver` does enforce the maximum takeoff weight.  
When the worker thread gets a result, it sets a static `_result` variable and
then sets the signal.

DoWork function in Airport

Notably, all the `Airport` code is implemented with threads but is not
designed to simultaneously process multiple planes at the same `Airport`.  
We can however connect multiple times to the same aiport with our ticket,  
even to the same runway because it only reserved in `Airport.GetPlane`, after
providing a callsign in the session.  
Thus we can start loading multiple planes at nearly the same time, and the
first completed result will be set for all planes.  
We abuse this race condition for our exploit.

Our exploit strategy is as follows:

- Spawn several connections including reserve connection  
- Send callsign for all but reserve (I had to use "SPIN", maybe you'll get the reference)  
- Get plane data  
- Send problem depending on max weight  
 - More difficult problem for connections with small max weight (fraction of max weight, full number of containers; not too complex because of timeout)  
 - Simple one for large max weight (minimum possible number, all max weight already; quick solve)  
- Start simultaneously  
- Collect load configurations to find overloaded plane  
- If found check clearance  
 - Possibly finish takeoff of wrong plane and cancel rest (resets to runway state `Free` ?)  
 - Set runway state to reserved again with reserve connection (sending callsign now)  
 - Request clearance for overloaded plane  
- Try takeoff and crash overloaded plane at runway  
- Retry until all runways are blocked and we get the flag

I felt the need to write a well structured exploit for this problem to avoid
implementation problems,  
but that is of course handy for sharing the solution with you.  
You'll find it as my [PCaS exploit
gist](https://gist.github.com/Ik0ri4n/8bea87b96cff96316ee857058695eee0),  
you'll need to replace `rumble.host` with `localhost` though.  
Big thanks to Lukas, the author, I really enjoyed analyzing the challenge and
implementing the exploit!  
Also thanks to [Martin](https://blog.martinwagner.co/) for supporting me with
the edge cases and helping me keep my sanity.  

Original writeup (https://ik0ri4n.de/rumble-23/#pcas).