The **kipferl** challenge was very similar to **gipfel** with the only
difference being that the finite field Diffie-Hellman was replaced with
elliptic curve Diffie-Hellman over a weird curve over the same prime. As our
**gipfel** solution only used the group structure and the values $verA$ and
$shared$, we could adapt it to also work on **kipferl**. For the **gipfel**
solution go [here](https://ctftime.org/writeup/31900). There were a few twists
though:

- The generator $G$ could now lie on the original curve or on its twist. This made the simple speedup of **gipfel** above slightly more tricky, as we needed to test where the generator guess is to reduce by the correct order.  
- The scalar multiplication operations as implemented in the challenge are quite slow, and we needed to run quite a lot of them in the time limit of 2021 seconds.

To address these issues, we precomputed the possible generators for all
passwords together with information on whether they lied on the original curve
or twist curve and used parallelization for the rest. The script below
precomputes generator information in Sagemath.

	# Requires tqdm and pycryptodome  
	import json  
	from tqdm import tqdm  
	from Crypto.Hash import SHA256

	q = 0x3a05ce0b044dade60c9a52fb6a3035fc9117b307ca21ae1b6577fef7acd651c1f1c9c06a644fd82955694af6cd4e88f540010f2e8fdf037c769135dbe29bf16a154b62e614bb441f318a82ccd1e493ffa565e5ffd5a708251a50d145f3159a5  
	K = GF(q)  
	a, b = K(1), K(0)

	curve = EllipticCurve([a, b])

	def enc(a):  
		f = {str: str.encode, int: int.__str__}.get(type(a))  
		return enc(f(a)) if f else a

	def H(*args):  
		data = b'\0'.join(map(enc, args))  
		return SHA256.new(data).digest()

	if __name__ == "__main__":  
		print("Precomputing gs...")  
		gs = {}  
		for pw in tqdm(range(10**6)):  
			g = int(H(pw).hex(), 16)  
			try:  
				curve.lift_x(K(g))  
				mod = "orig"  
			except:  
				mod = "twist"  
			gs[pw] = {  
				"g": g,  
				"mod": mod  
			}

		with open("gs.json", "w") as f:  
			json.dump(gs, f)

Next the actual attack script in Python. We actually reduce by a square root
$r$ of the order of the original curve as its group structure is bi-cyclic
($\mathbb{Z}_r \times \mathbb{Z}_r$). With enough cores the script below gets
the flag.

	#!/usr/bin/env python3  
	from pwn import *  
	from Crypto.Hash import SHA256  
	from Crypto.Cipher import AES  
	from binascii import unhexlify  
	from multiprocessing import Pool  
	from tqdm import tqdm  
	import json

	q = 0x3a05ce0b044dade60c9a52fb6a3035fc9117b307ca21ae1b6577fef7acd651c1f1c9c06a644fd82955694af6cd4e88f540010f2e8fdf037c769135dbe29bf16a154b62e614bb441f318a82ccd1e493ffa565e5ffd5a708251a50d145f3159a5  
	a, b = 1, 0  
	order_orig = 21992493417575896428286087521674334179336251497851906051131955410904158485314789427947788692030188502157019527331790513011401920585195969087140918256569620608732530453375717414098148438918130733211117668960801178110820764957628836  
	order_sqrt = 4689615487177589107664782585032558388794418913529425573939737788208931564987743250881967962324438559511711351322406  
	order_twist = 2 * q + 2 - order_orig

	################################################################

	# https://www.hyperelliptic.org/EFD/g1p/data/shortw/xz/ladder/ladd-2002-it  
	def xDBLADD(P,Q,PQ):  
		(X1,Z1), (X2,Z2), (X3,Z3) = PQ, P, Q  
		X4 = (X2**2-a*Z2**2)**2-8*b*X2*Z2**3  
		Z4 = 4*(X2*Z2*(X2**2+a*Z2**2)+b*Z2**4)  
		X5 = Z1*((X2*X3-a*Z2*Z3)**2-4*b*Z2*Z3*(X2*Z3+X3*Z2))  
		Z5 = X1*(X2*Z3-X3*Z2)**2  
		X4,Z4,X5,Z5 = (c%q for c in (X4,Z4,X5,Z5))  
		return (X4,Z4), (X5,Z5)

	def xMUL(P, k):  
		Q,R = (1,0), P  
		for i in reversed(range(k.bit_length()+1)):  
			if k >> i & 1: R,Q = Q,R  
			Q,R = xDBLADD(Q,R,P)  
			if k >> i & 1: R,Q = Q,R  
		return Q

	################################################################

	def enc(a):  
		f = {str: str.encode, int: int.__str__}.get(type(a))  
		return enc(f(a)) if f else a

	def H(*args):  
		data = b'\0'.join(map(enc, args))  
		return SHA256.new(data).digest()

	def F(h, x):  
		r = xMUL((h,1), x)  
		return r[0] * pow(r[1],-1,q) % q

	def test_F(args):  
		password, g, verA, exp = args  
		out = F(g, exp)  
		if verA == out:  
			return True, password, g  
		else:  
			return False, password, g

	def solve_pow(server):  
		pow_regex = re.compile(r"\"([0-9a-f]+)\"")  
		bits_regex = re.compile("([0-9]+) zero")

		pow_line = server.recvline()  
		pow_challenge = pow_regex.search(pow_line.decode()).groups()[0]  
		pow_bits = bits_regex.search(pow_line.decode()).groups()[0]

		pow_proc = subprocess.run(["./pow-solver", pow_bits, pow_challenge], capture_output=True)  
		pow_res = pow_proc.stdout.strip()

		server.sendline(pow_res)

	def decrypt(password, shared, data):  
		key = H(password, shared)  
		aes = AES.new(key, AES.MODE_CTR, nonce=b'')  
		return aes.decrypt(unhexlify(data))

	if __name__ == "__main__":  
log.info("Loading gs...")  
		with open("gs.json") as f:  
			gs = json.load(f)

		server = remote("65.108.176.252", 1099)  
log.info("Solving PoW")  
		solve_pow(server)  
		log.success("Solved PoW")

		pubA = int(server.recvline().strip().decode().split(" = ")[1], 16)

		server.sendline(b"2")

		verA = int(server.recvline().strip().decode().split(" = ")[1], 16)

		server.sendline(b"2") # This will fail and we will get shared.

		shared = int(server.recvline().strip().decode().split("! ")[1], 16)  
		exp_orig = shared**3 % order_sqrt  
		exp_twist = shared**3 % order_twist

		tasks = [(int(password), val["g"], verA, exp_orig if val["mod"] == "orig" else exp_twist) for password, val in gs.items()]

		pool = Pool()  
		res = pool.imap_unordered(test_F, tasks)  
		for r in tqdm(res, total=len(gs)):  
			if r[0]:  
				password = r[1]  
				g = r[2]  
				pool.terminate()  
				pool.join()  
				break  
		else:  
			log.error("No luck")  
			exit(1)  
		log.success(f"We got the g: {g}")  
		log.success(f"We got the password: {password}")

log.info("---- Second run ----")

		pubA = int(server.recvline().strip().decode().split(" = ")[1], 16)

		privB = 10  
		pubB = F(g, privB)

		server.sendline(str(pubB).encode())

		verA = int(server.recvline().strip().decode().split(" = ")[1], 16)

		shared = F(pubA, privB)  
		assert verA == F(g, (shared**3))  
		verB = F(g, (shared**5))

		server.sendline(str(verB).encode())

		encrypted_flag = server.recvline().strip().decode().split(": ")[1]  
		log.success(f"The flag is {decrypt(password, shared, encrypted_flag)}")

		server.close()

Original writeup (https://neuromancer.sk/article/30#kipferl).