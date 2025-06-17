import json
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

headers = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Cookie":"_ym_uid=1683173622461585620; _ym_d=1714976857; cookieconsent_status=dismiss; csrftoken=b1AnUGvL87BOxp3eoJwHYgnHL5Exd7m8; __utmz=225924040.1716947594.17.7.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); sessionid=71024df1d03401f9d2a9596011ef2b60; __utma=225924040.1393055870.1714976856.1720272414.1722586471.19; __utmc=225924040; _ym_isad=2; _ym_visorc=w; __utmb=225924040.4.10.1722586471",
}

# 加载JSON文件
with open('list.json', 'r', encoding='utf-8') as f:
    problems = json.load(f)

# 定义一个函数来解析HTML并找到对应题目的分值
def get_scores(html_content, problem_name):
    soup = BeautifulSoup(html_content, 'html.parser')
    table = soup.find('table', {'class': 'table table-striped'})
    rows = table.find_all('tr')
    
    problem_score = -1.0
    max_score = -1.0
    
    for row in rows[1:]:  # Skip the header row
        cols = row.find_all('td')
        if len(cols) > 0:
            score_text = cols[1].text.strip()
            first_score = score_text.split('+')[0]  # 取第一个分数

            try:
                score_value = float(first_score)
            except:
                score_value = -1.0
            
            # 更新最大分值
            if score_value > max_score:
                max_score = score_value
            
            # 找到特定题目的分值
            if cols[0].text.strip() == problem_name:
                problem_score = int(score_value) if score_value.is_integer() else score_value
    
    # 如果最大分值是整数，返回整数，否则返回浮点数
    max_score = int(max_score) if max_score.is_integer() else max_score
    return problem_score, max_score


# 遍历每个题目并更新分值
for problem in tqdm(problems):
    problem_name = problem["name"]
    competition_url = problem["competition"][1]
    
    # 通过requests库获取HTML内容
    # print(competition_url)
    response = requests.get(competition_url, headers=headers)
    # print(response.text)

    if response.status_code == 200:
        html_content = response.text
    
        # 获取分值
        score, max_score = get_scores(html_content, problem_name)

        # 更新JSON对象
        if score is not None:
            problem["score"] = score
        if max_score is not None:
            problem["max_score"] = max_score

        if score != -1 and max_score != -1:
            problem["difficuly"] = score / max_score
        else:
            problem["difficuly"] = -1

    else:
        print(f"Failed to retrieve URL: {competition_url}")

    with open('list.json', 'w', encoding='utf-8') as f:
        json.dump(problems, f, ensure_ascii=False, indent=4)
