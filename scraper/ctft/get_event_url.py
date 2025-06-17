from ctft.souper import souper
from bs4 import BeautifulSoup
import re
import inquirer
from inquirer.themes import GreenPassion
 

 

async def get_ctf_list():
    
    url = "https://ctftime.org/event/list/past"
    
    
    print(" Accessing CTFTime archive")
     
    soup = await souper(url)
    
    if not soup:
        print("Cannot access CTFtime.org. Try again")
        return
    
    rows = soup.find_all("tr")
    ctf_list = {}
    for row in rows[1:]:
        name = row.find("a").text
        # print(name)
        href = row.a['href']
        ctf_list[name] = href
     
    return ctf_list

async def find_ctf_url(name):
    
    ctf_list = await get_ctf_list()
    
    ctfs = []
    
    name.replace(" ","")
    for event in ctf_list.keys():
        ev = event
        event  = re.sub(" ","",event)
        if name.lower() in event.lower():  
            ctfs.append((ev,ctf_list[ev]))   
    if not ctfs:
        print("No match found :(")
        return
    
    ques = [ inquirer.List('event',message="Choose event", choices= ctfs) ]
    ans = inquirer.prompt(ques,theme=GreenPassion())
    
    url = "https://ctftime.org" + ans['event'] + "/tasks/"
    return url
