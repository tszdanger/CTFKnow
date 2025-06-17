# gg no re

## Description

> http://challenges.auctf.com:30022  
>  
> A junior dev built this site but we want you to test it before we send it to
> production.

## Solution

The website if a simple html page, but looking at the source code, we see that
it has a line

```html  
<script>authentication.js</script>  
```

So I look for the file in the url, it gives

```js  
var
_0x44ff=['TWFrZSBhIEdFVCByZXF1ZXN0IHRvIC9oaWRkZW4vbmV4dHN0ZXAucGhw','aW5jbHVkZXM=','bGVuZ3Ro','bG9n'];(function(_0x43cf52,_0x44ff2a){var
_0x2ad1c9=function(_0x175747){while(--_0x175747){_0x43cf52['push'](_0x43cf52['shift']());}};_0x2ad1c9(++_0x44ff2a);}(_0x44ff,0x181));var
_0x2ad1=function(_0x43cf52,_0x44ff2a){_0x43cf52=_0x43cf52-0x0;var
_0x2ad1c9=_0x44ff[_0x43cf52];if(_0x2ad1['UmZuYF']===undefined){(function(){var
_0x4760ee=function(){var
_0x335dc0;try{_0x335dc0=Function('return\x20(function()\x20'+'{}.constructor(\x22return\x20this\x22)(\x20)'+');')();}catch(_0x3b3b3e){_0x335dc0=window;}return
_0x335dc0;};var _0x1ecd5c=_0x4760ee();var
_0x51e136='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';_0x1ecd5c['atob']||(_0x1ecd5c['atob']=function(_0x218781){var
_0x1c7e70=String(_0x218781)['replace'](/=+$/,'');var _0x1fccf7='';for(var
_0x2ca4ce=0x0,_0x55266e,_0x546327,_0x17b8a3=0x0;_0x546327=_0x1c7e70['charAt'](_0x17b8a3++);~_0x546327&&(_0x55266e=_0x2ca4ce%0x4?_0x55266e*0x40+_0x546327:_0x546327,_0x2ca4ce++%0x4)?_0x1fccf7+=String['fromCharCode'](0xff&_0x55266e>>(-0x2*_0x2ca4ce&0x6)):0x0){_0x546327=_0x51e136['indexOf'](_0x546327);}return
_0x1fccf7;});}());_0x2ad1['hdhzHi']=function(_0x5d9b5f){var
_0x24b0b1=atob(_0x5d9b5f);var _0x5c5f21=[];for(var
_0x390988=0x0,_0xd8eac0=_0x24b0b1['length'];_0x390988<_0xd8eac0;_0x390988++){_0x5c5f21+='%'+('00'+_0x24b0b1['charCodeAt'](_0x390988)['toString'](0x10))['slice'](-0x2);}return
decodeURIComponent(_0x5c5f21);};_0x2ad1['wrYKfR']={};_0x2ad1['UmZuYF']=!![];}var
_0x175747=_0x2ad1['wrYKfR'][_0x43cf52];if(_0x175747===undefined){_0x2ad1c9=_0x2ad1['hdhzHi'](_0x2ad1c9);_0x2ad1['wrYKfR'][_0x43cf52]=_0x2ad1c9;}else{_0x2ad1c9=_0x175747;}return
_0x2ad1c9;};function
authenticate(_0x335dc0){if(validate(_0x335dc0)){console[_0x2ad1('0x2')](_0x2ad1('0x3'));}};function
validate(_0x3b3b3e){return
_0x3b3b3e[_0x2ad1('0x1')]>=0x5&&_0x3b3b3e[_0x2ad1('0x0')]('$');}  
```

This is unreadable, but looking at the first line I see some string that look
like base64. I decode the first one with https://www.asciitohex.com/, it gives
`Make a GET request to /hidden/nextstep.php`.

So I go to http://challenges.auctf.com:30022/hidden/nextstep.php, which
doesn't give us much, simple html page. I look for Network tab in the
Inspector and look at the response header, and indeed there is the added
header `ROT13: Znxr n CBFG erdhrfg gb /ncv/svany.cuc` (it can also be a
different header with a different encoding). This is a ROT13, or caesar code.
I give it to https://www.asciitohex.com/, and it says `Make a POST request to
/api/final.php`.

I use Postman to do this. The response says `Send a request with the flag
variable set`. So I add a form-data body with name `flag` and no value, send
the request and it gives the flag.

Flag: `auctf{1_w@s_laZ_w1t_dis_0N3}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/AUCTF2020/Web/gg_no_re.md).