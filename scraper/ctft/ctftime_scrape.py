from bs4 import BeautifulSoup
from ctft.souper import souper
import html2text
import re
from ctft.formatter import formatter
from ctft.github_scrape import github_scraper
import os

home = '.'
path = 'write_ups'

def sanitize_filename(filename):
    # 将文件名中的特殊字符替换为下划线
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    return sanitized

def trim_spaces(s):
    # 删除开头的空格和换行符
    start = 0
    while start < len(s) and (s[start] == ' ' or s[start] == '\n'):
        start += 1
    
    # 删除结尾的空格和换行符 
    end = len(s) - 1
    while end >= 0 and (s[end] == ' ' or s[end] == '\n'):
        end -= 1
    
    # 返回修剪后的子串
    return s[start : end+1]

async def ctftime_scraper(url,session):
    print("Parsing {}".format(url))
    soup = await souper(url,session)
    
    #Make event directory
    ul = soup.find('ul',{'class':'breadcrumb'})
    if not ul:
        print("No ul"+url)
    li = ul.find_all('li')
    d = 'F:/research/CTFBench/dataset/raw/'
    os.chdir(d)

    #Writeup content
    container = soup.find_all("div",{"class":"container"})[1]

    #Configure html2text
    h = html2text.HTML2Text()
    h.ignore_links = True

    heading = container.find('div',{'class':'page-header'})
    file_name = sanitize_filename(heading.h2.text.strip()) + '.md'

    #Find writeup content and format it
    writeup_html = str(soup)
    
    if '<!-- markdown parser here -->' not in writeup_html:
        print("Writeup for {} passed".format(file_name))
        return ()

    idx1 = writeup_html.find('<!-- markdown parser here -->')
    idx2 = writeup_html.find('Comments')

    writeup_html = writeup_html[idx1 + 30:idx2 - 30]

    f = open(file_name,"a", encoding="utf-8")
    f.write(trim_spaces(h.handle(writeup_html)))
    
    f.close()
    
    print("Writeup for {} saved in {}".format(file_name,d))
    return (file_name[:-3], d + file_name)