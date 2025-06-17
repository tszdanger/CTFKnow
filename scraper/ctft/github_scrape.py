from bs4 import BeautifulSoup
from ctft.souper import souper
import html2text
from ctft.formatter import formatter
import asyncio
import re
async def github_scraper(url):
    soup = await souper(url)
    article = soup.find("article")
    if article:
        markdwn = formatter(article)
        return markdwn
    if re.search("blob",url):
        c = '<a href="{}" >Original writeup</a>'.format(url)
        soup2 = BeautifulSoup(c,'html.parser')
        markdwn = formatter(soup2)
        return markdwn
