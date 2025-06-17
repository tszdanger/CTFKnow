## Writeup for challenge 'trustworthy'

This is a experimental task I made since I think Windows is not well-explored
in CTF. So you can take this as a movement to encourage CTF players to learn
more about Windows. :)

For the challenge description, please see distribution package in
[challenge](/challenges/) folder.

The origin of this challenge is a presentation from James Forshaw (see
reference).

To explain the logic of `server.exe` roughly : It checks the identity upon
client connection, the check is done by enumerating threads in the client
process and use `AccessCheck` to check the access from the thread token (if
not present, use the primary token) against the security descriptor of
`C:\token.txt`.

The intended solution involves using
[S4U](https://blogs.msdn.microsoft.com/winsdk/2015/08/28/logon-as-a-user-
without-a-password/) mechanism to obtain an IdentificationLevel impersonation
token. Note the first hint suggest you about impersonation. (See the API
documentation)

For more details, see [solution.cpp](solution.cpp) for more details.

## References

* [Slides of James Forshaw](https://www.slideshare.net/Shakacon/social-engineering-the-windows-kernel-by-james-forshaw)  

Original writeup
(https://github.com/Nu1LCTF/n1ctf-2018/blob/master/writeups/pwn/trustworthy/Writeup.md).