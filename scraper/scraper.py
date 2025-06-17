from bs4 import BeautifulSoup
from tqdm import *
from ctft.get_writeup_url import list_writeups
import asyncio
import json

def analyze_table(html):
    print('Get competitions...')
    soup = BeautifulSoup(html, 'html.parser')
    rows = soup.find_all('tr')
    competitions = []

    for row in tqdm(rows):
        cells = row.find_all('td')
        idx_name, idx_url = 0, 1
        if len(cells) == 3:
            idx_name, idx_url = 1, 2
            
        competition_name = cells[idx_name].find('a')['href'][5:]
        try:
            competition_url = cells[idx_url].find('a', string='CTFtime')['href']
            competitions.append((competition_name, competition_url))
        except:
            pass

    return competitions

async def analyze_competition(competitions):
    data_file = 'F:/research/CTFBench/dataset/data.json'
    data = []

    with open(data_file, 'r') as f:
        data = json.load(f)

    for competition in tqdm(competitions):
        results = await list_writeups(competition[1])
        if results:
            for result in results:
                if result:
                    dump = {
                        "competition": competition,
                        "challange": result[0],
                        "write-up": result[1]
                    }
                    data.append(dump)

        with open(data_file, 'w') as f:
            json.dump(data, f, indent=4)
    
    print('Finished.')

async def main():
    competitions = analyze_table(open('all.md', 'r').read())
    await analyze_competition(competitions)

if __name__ == "__main__":
    asyncio.run(main())