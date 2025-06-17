# Description  
We are given source of dns server

```  
import time  
from dnslib.server import DNSServer, BaseResolver  
from dnslib import RR, TXT, QTYPE, RCODE

class Resolver(BaseResolver):  
   def resolve(self, dns_record, handler):  
       """  
       handler.request is (data, socket)  
       """  
       reply = dns_record.reply()  
       reply.header.rcode = RCODE.reverse['REFUSED']

       print(len(handler.request[0]), handler.request[0])  
       if len(handler.request[0]) > 72:  
           return reply

       if dns_record.get_q().qtype != QTYPE.TXT:  
           return reply

       qname = dns_record.get_q().get_qname()  
       if qname == 'free.flag.for.flag.loving.flag.capturers.downunderctf.com':  
           FLAG = open('flag.txt', 'r').read().strip()  
           txt_resp = FLAG  
       else:  
           txt_resp = 'NOPE'

       reply.header.rcode = RCODE.reverse['NOERROR']  
       reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(txt_resp)))  
       return reply

server = DNSServer(Resolver(), port=8053)  
server.start_thread()  
while server.isAlive():  
   time.sleep(1)

```

Basiclly we need to send txt query for domain
`free.flag.for.flag.loving.flag.capturers.downunderctf.com`. But what a
problem that we must fit into 72 bytes.

- header takes 12 bytes ([see format](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1))  
- question section take `len(query) + 2 + 4 = 57 + 2 + 4  = 63` ([see format](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2))

so we need somehow reduce our request atleast at 3 bytes

# Solution  
My first thought was: there are some tricks in `dnslib` that can implement
super set of dns protocol. Lib has not much star, and maybe we can safe 3
bytes somewhere. But it is not the case.

However reading source code, I find out way to compress qustation ([see
this](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4)). But it
apear that it only applies to **multiple** quiries sharing same end part. like
`calenader.google.com` and `google.com`. it basiclly reusing another query by
jumping to address.

After some time I come up with idea: we can't add new queries, but what if we
reuse some not important part of whole dns request.

And here we go: we can put 4 bytes representing the end label `.com` in
header. That replace id + flags.

By doing this we safe 4 bytes - 1 byte for pointer. 3 bytes is enough. So we
can write code:

```  
from struct import pack  
import socket

header = b'\x03com'

counts = pack('!HHHH', 1,0,0,0)

TXT=16  
target='free.flag.for.flag.loving.flag.capturers.downunderctf.com'  
qname = [bytes([len(l)]) + l for l in target.encode().split(b'.')[:-1]]  
qs = b''.join(qname) + pack('!H', 0b1100_0000_0000_0000) + pack('!HH', TXT, 1)

msg = header + counts + qs

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
s.sendto(msg, ('localhost', 8053))  
print(s.recv(200))

```