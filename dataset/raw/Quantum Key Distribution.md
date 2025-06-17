# Quantum Key Distribution - Writeup  
##### By *sh4d0w58*

### Description:  
>We are simulating a Quantum satellite that can exchange keys using qubits
implementing BB84. You must POST the qubits and basis of measurement to
`/qkd/qubits` and decode our satellite response, you can then derive the
shared key and decrypt the flag. Send 512 qubits and basis to generate enough
key bits.

> **Flag:**
> U2FsdGVkX19OI2T2J9zJbjMrmI0YSTS+zJ7fnxu1YcGftgkeyVMMwa+NNMG6fGgjROM/hUvvUxUGhctU8fqH4titwti7HbwNMxFxfIR+lR4=

### Solution:

See [here](https://qt.eu/understand/underlying-principles/quantum-key-
distribution-qkd/) for a full explanation of how **Quantum Key Distribution**
works.

First we need to generate the qubits and basis. To make things simpler, we set
each qubit to `0+1j` and each basis to `"+"`. This means that every qubit,
when measured, will result in a `1`. There are actually three other
combinations of qubits and basis which result in a known bit, but this is the
only one which does not get rejected and produce an error from the server
about our data not being random enough.  
```  
basis = ["+" for i in range(512)]  
qubits = [{"real": 0, "imag": 1} for i in range(512)]  
body = {"basis": basis, "qubits": qubits}  
```

Next we send our qubits and basis to the server and read the response.  
```  
url = "https://cryptoqkd.web.ctfcompetition.com/qkd/qubits"  
req = urllib2.Request(url)  
req.add_header('Content-Type','application/json')  
response = json.loads(urllib2.urlopen(req, json.dumps(body)).read())  
```

The server responds with its basis and an `announcement` - our shared key
containing (presumably XORed with) the encryption key for the flag. We can
compute the shared key by comparing our basis with the server's and and
discarding the (qu)bits when they do not match. We will then end up with the
bits that we share. However, in this case, we do not need to do this because
we know that all the bits in the shared key will be `1` because **every** sent
bit was. From the server response, we know the key should be 128 bits long, so
therefore it is `2**128-1` (`11111..11` in binary). And we simply XOR the
shared key with the `announcement` to get the encryption key.  
```  
server_basis = response["basis"]  
announcement = int(response["announcement"],16)  
shared_key = 2**128-1  
print(hex(announcement^shared_key))  
```

This gives us the encryption key, `0x946cff6c9d9efed002233a6a6c7b83b1`. We can
then use this to decrypt the flag,
`U2FsdGVkX19OI2T2J9zJbjMrmI0YSTS+zJ7fnxu1YcGftgkeyVMMwa+NNMG6fGgjROM/hUvvUxUGhctU8fqH4titwti7HbwNMxFxfIR+lR4=`  
```  
$ echo "946cff6c9d9efed002233a6a6c7b83b1" > /tmp/plain.key; xxd -r -p
/tmp/plain.key > /tmp/enc.key  
$ echo "U2FsdGVkX19OI2T2J9zJbjMrmI0YSTS+zJ7fnxu1YcGftgkeyVMMwa+NNMG6fGgjROM/hUvvUxUGhctU8fqH4titwti7HbwNMxFxfIR+lR4=" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha1 -base64 --pass file:/tmp/enc.key  
```

The flag: `CTF{you_performed_a_quantum_key_exchange_with_a_satellite}`

### Full Code:  
```  
#!/usr/bin/env python  
import urllib2  
import json

basis = ["+" for i in range(512)]  
qubits = [{"real": 0, "imag": 1} for i in range(512)]  
body = {"basis": basis, "qubits": qubits}

url = "https://cryptoqkd.web.ctfcompetition.com/qkd/qubits"  
req = urllib2.Request(url)  
req.add_header('Content-Type','application/json')  
response = json.loads(urllib2.urlopen(req, json.dumps(body)).read())

server_basis = response["basis"]  
announcement = int(response["announcement"],16)  
shared_key = 2**128-1  
print(hex(announcement^shared_key))  
```