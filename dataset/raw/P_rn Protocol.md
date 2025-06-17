Original writeup
(https://github.com/B34nB01z/writeups/blob/master/2020/hack.lu/P*rn%20Protocol/README.md).## Writeup p\*rn protocol  
#### Description  
I know you want it. But please don't talk dirty to me.

nc flu.xxx 2005

Challenge files:  
https://pwnhub.fluxfingers.net/static/chall/prnprotocol_abea9f87630a37c0209bb35a8f6ad847.zip  
---

In this task you are supposed to create a program that uses a custom protocol
to talk with the server.  
The protocol is documented in the PDF file in the task description.

Short summary of the protocol:  
* You can send multiple "packets" at once up to 4  
* The first packet must be a "Message ID"  
* The second packet must be an "Identifier"  
* The third and fourth packet can be whatever you like ( "Member ID", "Login", "Flag" etc)  
* If any error occurs, the server will send an error packet back to us that we need to parse.

A list of all Packet types and Errors are located in the script below. It
should be fairly easy to follow the different steps in the script.

The goal is to ask the server for the flag. but to do this we must be logged
in.

Here is what we need to do:  
1. We receive a Message ID, Identifier, and Member ID from the server. The message ID contains a sequence number, while the identifier is an identifier for our session. The server tells us that we need to request a Member ID, so that is our next step.  
2. We send a Message ID with the sequence number incremented by 1, identifier packet, and Member ID packet where we request a new member ID (see get_member_id function in the script).  
3. The server sends 2 member ID packets with a username and a password  
4. We need to login using the username and password. (see the login function in script for this). we request to log in, and then server asks for username and password. If it was a successful login it returns 0x02.  
5. Now we can ask for the flag (See get_flag function in script)

Remember to increment the sequence number by 1 for every new sequences of
packets you are sending and use the same identifier throughout the session

A lot of the documentation for the different codes sent from client and server
is in the script as docstrings

Script:

```python  
#!/usr/bin/env python3  
import binascii  
from pwn import *

host = args.HOST or 'flu.xxx'  
port = int(args.PORT or 2005)

def remote(argv=[], *a, **kw):  
   '''Connect to the process on the remote host'''  
   io = connect(host, port)  
   if args.GDB:  
       gdb.attach(io, gdbscript=gdbscript)  
   return io

def start(argv=[], *a, **kw):  
   '''Start the exploit against the target.'''  
   return remote(argv, *a, **kw)

class Packet:  
   """Class for packet"""  
  
   types = {  
       0x01: "Message ID",  
       0x02: "Identifier",  
       0x03: "Member ID",  
       0x04: "Login",  
       0x05: "Flag",  
       0xFF: "Error"  
   }  
  
   def __init__(self, arr):  
       self.length = int(arr[0])  
       self.type = int(arr[1])  
       self.data = arr[2:]  
self.name = self.types[self.type]

   def is_error(self):  
       return self.type == 0xff

   def get_error(self):  
       errors = {  
           0x01: "Received to many bytes only 32 bytes in total are allowed.",  
           0x02: "Received a payload with length < 2. Or very large size.",  
           0x03: "Calculated payload length differs from received payload length.",  
           0x04: "Received unknown payload type.",  
           0x05: "Received less than three payloads.",  
           0x06: "First payload is not Message ID.",  
           0x07: "Second payload is not Identifier.",  
           0x08: "Found a payload type a second time.",  
           0x09: "Received to many messages in this session.",  
           0x10: "Did not expect payload.",  
           0x11: "Received invalid message ID.",  
           0x20: "Did not expect payload.",  
           0x21: "Received invalid identifier.",  
           0x30: "Did not expect payload.",  
           0x31: "Client used server code 0x01.",  
           0x32: "Client used server code 0x03.",  
           0x33: "Client used server code 0x04.",  
           0x34: "Unknown code from client.",  
           0x40: "Did not expect payload.",  
           0x41: "Username is to short/long.",  
           0x42: "Password is to short/long.",  
           0x43: "Received invalid username.",  
           0x44: "Received invalid password.",  
           0x45: "Client send login without knowing the credentials.",  
           0x47: "Unknown code from client.",  
           0x50: "No Flag at this point."  
       }  
       if self.is_error():  
               return errors.get(ord(self.data), None)  
       return None

   def get_len(self):  
       return self.length

   def get_type(self):  
       return self.type  
  
   def get_data(self):  
       return self.data

   def get_hex_data(self):  
       return binascii.hexlify(self.data)

   def to_bytes(self):  
       return bytes([self.length, self.type]) + self.data

   def __repr__(self):  
       return f"[len:{self.length} type:{self.type} name:{self.name}] {self.get_hex_data()}"  
       return f"[len:{self.length} type:{self.type} name:{self.name}] {self.data}"

def get_packets(io):  
   while io.can_recv(timeout=1):  
       # Get length  
       length = ord(io.recvn(1))  
       pkt_data = io.recvn(length)  
       log.debug("Received (raw): {}".format(binascii.hexlify(bytes([length])+pkt_data)))  
  
       yield Packet(bytes([length]) + pkt_data)  

def login(io, seq_num, identifier, username, password):  
   """  
   Code Server Code Client Definition  
   -           0x01        Login request by client.  
   0x02        -           Successfull Login.  
   """

   # Message ID  
   pkt1 = Packet(b'\x02\x01'+seq_num)  
   # Identifier  
   pkt2 = Packet(b'\x11\x02'+identifier)  
   # Login  
   pkt3 = Packet(b'\x02\x04\x01')  
  
log.info(f"Sending login request: {pkt1} {pkt2} {pkt3}")  
   io.send(pkt1.to_bytes() + pkt2.to_bytes() + pkt3.to_bytes())

   io.recvuntil("Username: ")  
   io.sendline(username)  
   io.recvuntil("Password: ")  
   io.sendline(password)

   for pkt in get_packets(io):  
       if pkt.type == 1:  
           seq = pkt.data  
       elif pkt.type == 4:  
           if int(pkt.data[0]) == 2:  
               log.success("Login successful!")  
   return seq

def get_flag(io, seq_num, identifier):  
   """  
   Code Server Code Client Definition  
   -           0x01        Flag request.  
   """

   # Message ID  
   pkt1 = Packet(b'\x02\x01'+seq_num)  
   # Identifier  
   pkt2 = Packet(b'\x11\x02'+identifier)  
   # Ask for flag  
   pkt3 = Packet(b'\x02\x05\x01')  
  
log.info(f"Sending flag request: {pkt1} {pkt2} {pkt3}")  
   io.send(pkt1.to_bytes() + pkt2.to_bytes() + pkt3.to_bytes())

   for pkt in get_packets(io):  
       if pkt.type == 1:  
           seq = pkt.data  
       elif pkt.type == 5:  
           log.success(f"FLAG: {pkt.data.decode()}")  
   return seq

def get_member_id(io, seq_num, identifier):  
   """This payload controls the creation of new logins for the clients.  
   Code Server Code Client Definition  
   0x01        -           MemberID requested.  
   -           0x02        New MemberID required.  
   0x03        -           Everthing following after this byte is the
username.  
   0x04        -           Everthing following after this byte is the
password.  
   """

   # Message ID  
   pkt1 = Packet(b'\x02\x01'+seq_num)  
   # Identifier  
   pkt2 = Packet(b'\x11\x02'+identifier)  
   # request member ID  
   pkt3 = Packet(b'\x02\x03\x02')  
  
log.info(f"Requesting member ID: {pkt1} {pkt2} {pkt3}")  
   io.send(pkt1.to_bytes() + pkt2.to_bytes() + pkt3.to_bytes())

   for pkt in get_packets(io):  
       if pkt.type == 1:  
           seq = pkt.data  
       elif pkt.type == 3:  
           if int(pkt.data[0]) == 3:  
               username = pkt.data[1:]  
           elif int(pkt.data[0]) == 4:  
               password = pkt.data[1:]  
   return seq, username, password

io = start()

for pkt in get_packets(io):  
   log.success(pkt)  
   if pkt.type == 1:  
       seq = pkt.data

   if pkt.type == 2:  
       identifier = pkt.data

   if pkt.is_error():  
       log.error(pkt.get_error())

seq, username, password = get_member_id(io, seq, identifier)  
log.success(f"Got credentials: {username=} / {password=}")

seq = login(io, seq, identifier, username, password)  
get_flag(io, seq, identifier)

for pkt in get_packets(io):  
   log.success(pkt)  
   if pkt.is_error():  
       log.warning("Error from server: " + pkt.get_error())

io.interactive()  
```