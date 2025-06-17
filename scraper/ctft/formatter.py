from bs4 import BeautifulSoup
from ctft.souper import souper
import html2text
import re

# url = "https://github.com/enedil/ctf/tree/master/2020/PoseidonCTF/mixer"
def formatter(soup):
    
    #vmd doesn't support <br> tags so remove them
    for br in soup('br'):
        br.decompose()

    soup_html = soup.prettify()

    #convert to markdown 
    h = html2text.HTML2Text()
    h.ignore_links = False
    soup_markdwn = h.handle(soup_html)

    #Formatting to render code blocks 
    soup_markdwn = re.sub('[a-zA-Z0-9]*```[a-zA-Z0-9]*','\n```\n',soup_markdwn)
    
    #vmd doesn't support markdown of img so remove it
    soup_markdwn = re.sub("\!\[[a-zA-Z0-9]*\]","`IMAGE`",soup_markdwn)
    
    #handle lists
    soup_markdwn = re.sub('\\\-','\n- ',soup_markdwn)
    soup_markdwn = re.sub('(\d*)\\\.',r"\n\1.",soup_markdwn)
 

    #Return writeup
    return soup_markdwn

