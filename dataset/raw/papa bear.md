# papa bear - HackTM 2020 Quals
## Introduction

papa bear is a rev task.

The goal of this task is to find a flag that will make the output of a given
binary equal to the output given in the task's description.

The binary expects some user input as first argument.

It will then change its internal state depending on what was the user input, and
it will output an ASCII-art of a mustach with a lot of M. Some of these M are
changed into W in accordance to the input.

## Black-box crypto

After playing a bit with the binary, it looks like its algorithm will flip M
into W in a linear maneer. It means that if the `n` first characters of the
input match the flag, then the `m` first characters of the ASCII art will match
the reference art.

> Every RE is black-box crypto if you're brave enough

It is possible to write a script using an heuristic as simple as `score = number
of leftmost characters that match`.
This will solve this challenge without understanding the inner workings. 

There is one caveat: the binary appears to write on file descriptor 0 (which is
supposed to be for input). This can be fixed by redirecting fd 0 to fd 1
(standard input)

The charset is strange (it contains spaces), but the script is fast enough that
the whole printable range can be bruteforced.

**Flag**: `HackTM{F4th3r bEaR s@y$: Smb0DY Ea7 My Sb3VE}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php
const TARGET = "WWWWWMWWWWWMWMMMWWWWWWWWWMMMWMWWWWMWWWMMWMMMWWWWWMMMMMMWMMMWWWMMMMWWMWWMWWMMMMMMWWWWMMWWWMWWWWWWMMWWWWMWMWMMMWWWWMMMMMWMWMMMWMMWWWMWMMMMMMMMWMMMMWWWMMWWMWMWMMWWMWWWWMWWMMWMMWWWWWWWWMMWWWWWWWMMWWWWMMWWWWMWMMMMWWWWWMMWWMWWWWWWMWMWWWMMWWMWMWWWWMWWWWMWWMMMWMWMWWWWMMMMWWMMMMMMMMM";

function score($string)
{
	for($i = 0; $i < strlen(TARGET); $i++)
		if(TARGET[$i] !== $string[$i])
			break;

	return $i;
}

function check($password)
{
	$cmd = sprintf("./papa_bear %s 0>&1", escapeshellarg($password));
	$p   = popen($cmd, "r");

	/* Discard papa bear */
	for($i = 0; $i < 7; $i++)
		fgets($p);

	/* Read MW */
	$buffer = "";
	for($i = 0; $i < 7; $i++)
		$buffer .= fgets($p);

	fclose($p);

	/* Remove unwanted characters */
	$clear  = "pbdqPQ-= \n";
	$buffer =  str_replace(str_split($clear), "", $buffer);

	assert(275 === strlen($buffer));
	return $buffer;
}

$charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_/+";
$flag    = ""; //"HackTM{F4th3r bEaR s@y$: Smb0DY Ea7 My Sb3VE}";

while(false === strpos($flag, "}")) {
	$score = 0;
	$best  = [];

	//for($i = 0; $i < strlen($charset); $i++) {
	for($i = 0x20; $i < 0x7F; $i++) {
		$char = chr($i);
		//$char = $charset[$i];
		$c = check($flag . $char);
		$s = score($c);

		if($s == $score) {
			$best[] = $char;
		} else if($s > $score) {
			$score = $s;
			$best  = [$char];
		}
	//	printf("%d %s %d\n", $i, $charset[$i], score($c));
	}

	if(sizeof($best) !== 1) {
		var_dump($best);
		throw new Exception("too much");
	}

	$flag .= $best[0];
	printf("%s\n", $flag);
}
```