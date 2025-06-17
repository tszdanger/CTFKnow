## Challenge Information

- Name: RCE auditor  
- Type: Web  
- Description:

```  
Chrome has retired the XSS Auditor, but how about the RCE Auditor? The evil
`eval_server` is listening on `127.0.0.1:6666`, but RCE Auditor protects us.  
```

- Files provided: `docker/user/eval_server.c`  
- Solves: 1 / 720 

## Build

```  
docker-compose build  
docker-compose up

# attach bash for debugging  
docker ps  
docker exec -it <CONTAINER ID> bash  
```

## Writeup

The internal server listening on `localhost:6666` will read from inputs and
execute in shell line by line. However, Chromium (and Firefox) will [block any
access to port 6666](https://superuser.com/a/188070) due to `ERR_UNSAFE_PORT`.
It's designed to protect users from protocol smuggling attacks.

Thus, HTTP-based request (XHR/fetch/html) will fail to be sent. We have to
leverage other protocols. Though Chromium supports `ftp`, it's too difficult
to abuse `ftp` for protocol smuggling.

Nowadays, modern browser supports [WebRTC
API](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API). This API
aims for establishing peer-to-peer connection. During the negotiation,
[STUN](https://en.wikipedia.org/wiki/STUN) protocol is used to pick up [ICE
candidates](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment).

However, it's not trivial.

Specifying username and password in initializing WebRTC TURN server will not
work, because the TURN handshake has considered this protocol smuggling
attack.

1. Though username and password is controllable, it's not the first packet sent from the browser.  
2. Unless the browser receives a valid response, it will not send this authentication packet containing username and password.  
3. We cannot control any byte in the first handshake packet.

STUN server will not work either. The reason is the same as below.

Thus, we have to first establish a valid STUN protocol, and then somehow send
the packet to our target. The exploit utilizes ICE candidate and `ice-ufrag`
(or `ice-pwd`) in [RFC 5245](https://tools.ietf.org/html/rfc5245) to control
part of the packet. `ice-ufrag` and `ice-pwd` are used for authentication to
an ICE candidate server.

For full exploit, please see `exploit` directory.

## Postscript

The behavior of blocking unsafe port is interesting. One day I created a test
Python server on `0.0.0.0:6666`, I found that the browser itself blocked me
from accessing.

For WebRTC part, [it begins to follow CSP connect-src
policies](https://github.com/w3c/webrtc-nv-use-cases/issues/35) recently.
(This is [one of the challenge in RCTF](https://github.com/zsxsoft/my-ctf-
challenges/tree/master/rctf2019/jail%20%26%20password#jail)) Then I notice
that STUN protocol is not a HTTP protocol. Can we abuse this for something?
This challenge just combines the two idea.  

Original writeup (https://github.com/BookGin/my-ctf-
challenges/tree/master/balsn-ctf-2019/rce-auditor).