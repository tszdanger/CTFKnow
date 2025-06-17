import os
import re
import json
from tqdm import *

# 指定write_ups文件夹路径
folder_path = "raw"

description = [
    'Description', 
    'Clue', 
    'Problem', 
    'Overview',
    'Task',
    # 'description', 
    'clue', 
    'problem', 
    'overview',
    'task',
    ]

# pattern = re.compile(r'\[.*?\]\(.*?\.png\)')

# if string more than 10 lines
def less_than_10_lines(data):
    lines = data.split('\n')

    if len(lines) < 10:
        return True
    else:
        return False
    
def not_pasred(data):
    if '<html' in data:
        return True
    else:
        return False

def remove_empty_files():
    for file in os.listdir('raw'):
        file_path = os.path.join('raw', file)  # 构建完整的文件路径
        
        data = open(file_path, 'r', encoding="utf-8")
        if len(data.read()) == 0:
            print(file)
            data.close()
                
            os.remove(file_path)  # 删除文件时也需要使用完整路径

# if string more than 10 lines
def less_than_30_lines(data):
    lines = data.split('\n')

    if len(lines) < 30:
        return True
    else:
        return False
    
def not_have_description(data):
    if not is_any_substring(description ,data):
        return True
    else:
        return False
    
def have_image(data):
    if ('.png)' in data) or ('.jpg)' in data) :
        return True
    else:
        return False

def is_any_substring(strings, target):
    for s in strings:
        if s in target:
            return True
    return False

def main():
    
    for file in tqdm(os.listdir('raw')):
        # print(file)
        data = ''
        file_path = os.path.join('raw', file)  # 构建完整的文件路径
        with open(file_path, 'r', encoding='utf-8') as write_up:
            data = write_up.read()
        

        if less_than_30_lines(data) or not_have_description(data) or have_image(data) or not_pasred(data):
            # Delete the write-up file
            # print(path)
            os.remove(file_path)

if __name__ == "__main__":
    # remove_empty_files()
    main()