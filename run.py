import os
import json
import re
from tqdm import *
from openai import OpenAI
# from groq import Groq
# from volcenginesdkarkruntime import Ark
import replicate
import argparse
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np
from prompts import *

client = OpenAI(
    api_key=os.environ['OPENAI_API_KEY'],
)

def query_replicate(input, system_promt='You are a helpful assistant.', model="meta/meta-llama-3-70b-instruct", visible=True):
    input = input.replace("{", "")
    input = input.replace("}", "")
    prompt_template = f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n{system_promt}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n{input}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
    output = replicate.run(
    model,
    input={
        "top_k": 50,
        "top_p": 0.9,
        "prompt": "",
        "max_tokens": 2048,
        "min_tokens": 0,
        "temperature": 0,
        "prompt_template": prompt_template,
        "presence_penalty": 1.15,
        "frequency_penalty": 0.2
    },
    )
    res = ''.join(output)
    if visible:
        print(res)
    return res, 1

types = ['web', 'pwn', 'reverse', 'crypto', 'forensics', 'misc']

class BashExperience:
    """Extracting Bash Experience From NYU CTF Log files"""

    # May be not necessary
    pass

class Buildinit:
    """Build an initial file list of the bench"""
    def __init__(self, list_file_name ,write_up_path = 'dataset/raw', data_file_name = 'dataset/data.json'):
        self.write_up_path = write_up_path
        self.data_file_name = data_file_name
        self.list_file_name = list_file_name
        self.alldata = json.loads(open(data_file_name, 'r').read())
        self.result = []

        self.year = {}
        self.types = ['misc', 'crypto', 'web', 'reverse', 'forensics', 'pwn']
    
    def build(self):
        # read all files in write_up_path, build key "name" using the filenames
        print("Start Building...")
        for file in tqdm(os.listdir(self.write_up_path)):

            # read the write up file and judge the type.
            write_up = ''
            challange_type = ''
            path = os.path.join(self.write_up_path, file)
            with open(path, 'r', encoding="utf-8") as writeup_file:
                write_up = writeup_file.read()
            for type in types:
                if type in write_up.lower():
                    challange_type = type
            
            # if challange type is '', use LLM to determin
            if challange_type == '':
                try:
                    response = client.chat.completions.create(
                        messages=[
                            {"role": "system", "content": DETERMIN_TYPE},
                            {"role": "user", "content": write_up}
                        ],
                        model="gpt-3.5-turbo-0125",
                    )
                    challange_type = response.choices[0].message.content
                except:
                    pass

            self.result.append({
                "name": file.split('.')[0],
                "write_up": os.path.join(self.write_up_path, file), 
                "type": challange_type,
            })

        # using key "name" to retrail in the data file, get the year
        for item in tqdm(self.result):
            for data in self.alldata:
                if item["name"] in data["write-up"]:
                    item["competition"] = data["competition"]
                    break

        # write the result in list file
        with open(self.list_file_name, 'w') as file:
            json.dump(self.result, file, indent=4)
        
        print("Build Done.")

    def draw_graph(self):
        """Draw the graph of the year, type and the difficulty on the same figure."""
        year_count = {year: 0 for year in range(2019, 2025)}
        type_count = {type: 0 for type in self.types} 

        difficulty_intervals = [f"{(i+1)/10}" for i in range(10)] 
        difficulty_count = {interval: 0 for interval in difficulty_intervals}
        difficulty_count['unavailable'] = 0

        self.result = json.loads(open(self.list_file_name, 'r', encoding='utf-8').read())

        for item in self.result:
            for year in year_count.keys():
                if str(year) in item["competition"][0]:
                    year_count[year] += 1

            if "type" in item and item["type"] in type_count:
                type_count[item["type"]] += 1

            difficulty = item.get('difficulty') 
            if difficulty is not None and difficulty >= 0:
                interval_index = min(int(difficulty * 10), 9)  
                difficulty_interval = difficulty_intervals[interval_index]
                difficulty_count[difficulty_interval] += 1
            else:
                difficulty_count['unavailable'] += 1

        difficulty_count.pop('unavailable', None)

        plt.figure(figsize=(20, 5))
        gs = gridspec.GridSpec(1, 3, width_ratios=[0.7, 0.7, 1], wspace=0.3)

        colors = []
        ax0 = plt.subplot(gs[0])
        year_colors = plt.cm.Paired(np.arange(len(year_count)))
        # print(year_colors)
        bars = ax0.bar(year_count.keys(), year_count.values(), color='#92D5EE', width=0.7)
        ax0.set_xlabel('Year', fontdict={'size': 16})
        ax0.set_ylabel('Number of Challenges', fontdict={'size': 16})
        ax0.set_title('Challenge Distribution by Year', fontdict={'size': 16})
        ax0.set_xticks(list(year_count.keys()))
        ax0.tick_params(axis='x', labelsize=12)
        ax0.tick_params(axis='y', labelsize=12)
        for bar in bars:
            yval = bar.get_height()
            ax0.text(bar.get_x() + bar.get_width()/2, yval + 0.1, int(yval), ha='center', va='bottom')

        ax1 = plt.subplot(gs[1])
        type_colors = plt.cm.Paired(np.arange(len(type_count)))
        bars = ax1.bar(type_count.keys(), type_count.values(), color='#F59094', width=0.7)
        ax1.set_xlabel('Challenge Category', fontdict={'size': 16})
        ax1.set_ylabel('Number of Challenges', fontdict={'size': 16})
        ax1.set_title('Challenge Distribution by Category', fontdict={'size': 16})
        # ax1.tick_params(axis='x', rotation=15)
        ax1.tick_params(axis='x', labelsize=10)
        ax1.tick_params(axis='y', labelsize=12)
        for bar in bars:
            yval = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2, yval + 0.1, int(yval), ha='center', va='bottom')

        # 难度柱状图
        ax2 = plt.subplot(gs[2])
        difficulty_colors = plt.cm.Paired(np.arange(len(difficulty_count)))
        bars = ax2.bar(difficulty_count.keys(), difficulty_count.values(), color='#8BD2A6', width=0.7)
        ax2.set_xlabel('Challenge Difficulties', fontdict={'size': 16})
        ax2.set_ylabel('Number of Challenges', fontdict={'size': 16})
        ax2.set_title('Challenge Distribution by Difficulty', fontdict={'size': 16})
        # ax2.tick_params(axis='x', rotation=15)
        ax2.tick_params(axis='x', labelsize=12)
        ax2.tick_params(axis='y', labelsize=12)
        for bar in bars:
            yval = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2, yval + 0.1, int(yval), ha='center', va='bottom')

        # plt.tight_layout()
        # plt.show()
        plt.savefig('Challange_Distribution.pdf')


class Knowledge:   
    """Extract core knowledge and save them in json format"""

    def __init__(self, list_path, knowledge_path):
        self.list_path = list_path
        self.knowledge_path = knowledge_path
        # self.data = {}
        # self.result = json.loads(open(self.list_path, 'r').read())
        self.result = json.loads(open(self.knowledge_path, 'r').read())

    def parse_response(self, s):
        lines = s.strip().split('\n')
        types = ''
        tag = []
        knowledge = []

        current_item = ''
        ignore_content = True
        
        for i, line in enumerate(lines):

            if line.startswith(tuple(str(i)+'.' for i in range(1, 10))):  # 检查行首是否为1.~9.
                if current_item:
                    knowledge.append(current_item.strip())
                current_item = line.split('.', 1)[1]
                ignore_content = False
            elif not ignore_content:
                current_item += '\n' + line
        
            if current_item and i == len(lines) - 1:
                knowledge.append(current_item.strip())
                # print(knowledge)
            
        return knowledge

    def save_data(self):
        """Save the modified data back to a JSON file."""
        with open(self.knowledge_path, 'w') as out_file:
            json.dump(self.result, out_file, indent=4)

    def extract(self):

        # 切片是前闭后开
        for item in tqdm(self.result):

            if "knowledge" in item:
                continue

            # data = {}
            path = item["write_up"]
            with open(path, 'r', encoding="utf-8") as writeup_file:
                write_up = writeup_file.read()
            # data['write_up'] = path

            print('---------------------------------')
            print('file:',path)

            response = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT_EXTRACTION1},
                    {"role": "user", "content": write_up}
                ],
                model="gpt-4-0125-preview",
            )

            print(response.choices[0].message.content)
            item["knowledge"] = self.parse_response(response.choices[0].message.content)
            # self.result.append(data)

            self.save_data()

class Question:
    """Desingn single choice questions and save them in the json file"""

    def __init__(self, json_path, save_path, question_list_path):

        self.write_up_begin = '\n--------------WRITE-UP-BEGIN---------------------\n'
        self.knowledge_begin = '\n--------------KNOWLEDGE-BEGIN-------------------\n'
        self.json_path = json_path
        self.save_path = save_path # save_path must NOT the same as json path
        self.question_list_path = question_list_path # Only the questions
        self.result = []
        self.question_list = []

        with open(json_path, 'r') as file:
            self.json = json.loads(file.read())

        with open(save_path, 'a') as file:
            pass

        with open(question_list_path, 'a') as file:
            pass

    def generate(self):

        for item in tqdm(self.json):
            # constrct the prompt
            writeup_path = item["write_up"]
            with open(writeup_path, 'r', encoding="utf-8") as file:
                writeup = file.read()

            prompt = ''
            knowledge = ''
            for i, string in enumerate(item["knowledge"]):
                knowledge += str(i + 1) + "." + string + "\n"
        
            prompt = self.write_up_begin + writeup + self.knowledge_begin + knowledge

            # generate_reply
            response = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT_QUESTION_GEN},
                    {"role": "user", "content": prompt}
                ],
                model="gpt-4-0125-preview",
            )

            print(response.choices[0].message.content)
            
            dict_ret = self.parse(response.choices[0].message.content)
            print("------------------------")
            item["question"] = dict_ret["question"]
            item["answer"] = dict_ret["answer"]

            questions = [{} for _ in range(len(dict_ret["question"]))]

            try:
                for i in range(len(dict_ret["question"])):
                    questions[i]["question"] = dict_ret["question"][i]
                    questions[i]["answer"] = dict_ret["answer"][i]
            except:
                continue

            self.result.append(item)
            self.question_list += questions

            with open(self.save_path, 'w') as file:
                json.dump(self.result, file, indent=4)

            with open(self.question_list_path, 'w') as file:
                json.dump(self.question_list, file, indent=4)

        return self.result

    def convert_question(self, original_question):
        # 提取题目和答案
        question_text = original_question["question"]
        answer_key = original_question["answer"]
        
        question_text = question_text.replace("which of the following", "which")
        
        # 提取参考答案
        # 假设答案是以 " - A. answer" 的格式给出
        answer_start = question_text.find(f" - {answer_key}.") + 5  # 跳过" - A."等
        
        answer_key_next = chr(ord(answer_key[0]) + 1)
        answer_end = question_text.find(f" - {answer_key_next}", answer_start)  # 查找下一个选项的开始
        reference_answer = question_text[answer_start:answer_end].strip() if answer_end != -1 else question_text[answer_start:].strip()
        
        # 更新原始数据
        original_question["short_answer_question"] = question_text.split(" - A.")[0].strip()  # 以选项A作为分隔，提取简答题题面
        original_question["reference_answer"] = reference_answer
        
        return original_question

    def convert_questions(self):
        with open(self.question_list_path, 'r', encoding='utf-8') as f:
            questions = json.load(f)
        
        # 假设questions是一个字典列表
        converted_questions = [self.convert_question(question) for question in tqdm(questions)]
        
        # 保存处理后的数据
        with open(self.question_list_path, 'w', encoding='utf-8') as f:
            json.dump(converted_questions, f, ensure_ascii=False, indent=4)

    def parse(self, data):

        pattern = r'^[0-9]\.'
        questions = []
        answers = []
        current_question = []
    
        for line in data.split('\n'):
            line = line.strip()
            if line.startswith('Answer:'):
                answers.append(line.split(': ')[1])
                questions.append(' '.join(current_question))
                current_question = []
            elif re.match(pattern, line):
                if line[2] == ' ':
                    line = line[3:]
                else:
                    line = line[2:]

                if current_question:
                    questions.append(' '.join(current_question))
                    current_question = [line]
                else:
                    current_question.append(line)
            else:
                if current_question:
                    current_question.append(line)

        result = {
            "question": questions,
            "answer": answers
        }

        return result
    
    # 从result中每个item提取包含"name", "type", "difficulty"和独立一个"question"的json
    def extract_question(self, list_path, save_path):
        all_list = []
        question_list = []
        with open(list_path, 'r') as file:
            all_list = json.loads(file.read())
        
        for item in tqdm(all_list):
            for i, question in enumerate(item["question"]):
                question_list.append(
                    {
                        "name": item["name"],
                        "type": item["type"],
                        "difficulty": item["difficulty"],
                        "question": question, 
                        "answer": item["answer"][i],
                        }
                    )

        # save the question list
        with open(save_path, 'w') as file:
            json.dump(question_list, file, indent=4)

class Envaluation:

    def __init__(self, llm, question_path):
        self.llm = llm
        self.question_path = question_path

        with open(question_path, 'r', encoding='utf-8') as question_file:
            self.questions = json.loads(question_file.read())

        self.question_numbers = len(self.questions)
        self.correct = 0
        self.incorrect = 0
        self.undesired = 0

    def envaluate(self):
        
        if self.llm in ["llama3-70b-8192", "mixtral-8x7b-32768"]:
            client = Groq(
                    api_key=os.environ["GROQ_API_KEY"],
                )
            
        for question in tqdm(self.questions):
            prompt = question["question"]

            print(prompt)
            # generate_reply
            response = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT_ENVALUATE},
                    {"role": "user", "content": prompt}
                ],
                model=self.llm,
            )

            print(response.choices[0].message.content[0])

            if response.choices[0].message.content[0] in "ABCD":
                if response.choices[0].message.content[0] == question["answer"][0]:
                    self.correct += 1
                    question[self.llm] = "correct"
                    print('correct')
                else:
                    self.incorrect += 1
                    question[self.llm] = "incorrect"
                    print('incorrect')
            else:
                self.undesired += 1
                question[self.llm] = "undesired"
                print('undesired')

            print('---------------------------')

            #   save file to self.question_path
            with open(self.question_path, 'w', encoding='utf-8') as file:
                json.dump(self.questions, file, indent=4)

        correct_rate = self.correct / self.question_numbers
        incorrect_rate = self.incorrect / self.question_numbers
        undesired_rate = self.undesired / self.question_numbers

        return correct_rate, incorrect_rate, undesired_rate

    def envaluate_short_answer(self):

        for question in tqdm(self.questions):

            if "short_answer_results" not in question:
                question["short_answer_results"] = []
            else:
                continue
            
            record = {"llm": self.llm}
            prompt = question["short_answer_question"]

            print(prompt)

            res, _ = query_replicate(prompt, system_promt=ANSWER_SHORT_ANSWER_QUESTION, model=self.llm)

            # print(response.choices[0].message.content)
            # record["answer"] = response.choices[0].message.content

            # print(res)
            record["answer"] = res

            # envaluate

            # prompt = "Question:" + question["short_answer_question"] \
            #     + "\n---------------reference-answer-----------------\n" + question["reference_answer"]  \
            #     + "\n---------------answer-from-the-respondent-----------------\n" + response.choices[0].message.content
            
            prompt = "Question:" + question["short_answer_question"] \
                + "\n---------------reference-answer-----------------\n" + question["reference_answer"]  \
                + "\n---------------answer-from-the-respondent-----------------\n" + res
            
            messages=[
                    {"role": "system", "content": ENVALUATE_SHORT_ANSWER},
                    {"role": "user", "content": prompt}
            ]

            response = client.chat.completions.create(
                messages=messages,
                model="gpt-4-0125-preview",
            )

            print(response.choices[0].message.content)
            record["judge"] = response.choices[0].message.content
            # CoT
            # message = CoT_ENVALUATE_SHORT_ANSWER.format(answer=question["reference_answer"])
            # print(message)

            # messages.append({"role":"user", "content":message})
            # response = client.chat.completions.create(
            #     messages=messages,
            #     model="gpt-4-0125-preview",
            # )

            # print(response.choices[0].message.content)
            
            # record["judge2"] = response.choices[0].message.content

            question["short_answer_results"].append(record)

            with open(self.question_path, 'w') as file:
                json.dump(self.questions, file, indent=4)

        return True
    # def get_result(self):
    #     pass

class BuildKey:
    """Bulid Key in vector DB to be retrieval"""
    def __init__(self, json_path, save_path):
        self.json_path = json_path
        self.save_path = save_path # save_path must NOT the same as json path
        self.result = []
        self.json = []

        with open(json_path, 'r') as file:
            self.json = json.loads(file.read())

        with open(save_path, 'a') as file:
            pass
    
    def build_key(self, prompt, key_name):

        for item in tqdm(self.json):
            # constrct the prompt
            writeup_path = item["write_up"]
            with open(writeup_path, 'r', encoding="utf-8") as file:
                writeup = file.read()

            response = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": writeup}
                ],
                model="gpt-4o-2024-08-06",
                temperature=0,
            )

            print(response.choices[0].message.content)
            
            print("------------------------")
            item[key_name] = response.choices[0].message.content

            # self.result.append(item)

            with open(self.save_path, 'w') as file:
                json.dump(self.json, file, indent=4)

        return self.json
    
    def build(self):
        # self.build_key(BUILD_KEY_SENCE, "key_sence")
        # self.build_key(BUILD_KEY_VULN, "key_vuln")
        self.build_key(BUILD_KEY_CODE, "key")

def main():
    parser = argparse.ArgumentParser(description="CTF Challenge Processing Tool")
    
    subparsers = parser.add_subparsers(dest="command")

    # Knowledge Extraction
    parser_k = subparsers.add_parser('K', help='Knowledge Extraction')
    parser_k.add_argument('-i', '--input', required=True, help='Input list file for knowledge extraction')
    parser_k.add_argument('-o', '--output', required=True, help='Output file for extracted knowledge')

    # Question Generation
    parser_q = subparsers.add_parser('Q', help='Question Generation')
    parser_q.add_argument('-i', '--input', required=True, help='Input file for question generation')
    parser_q.add_argument('-o', '--output', required=True, help='Output file for generated questions')
    parser_q.add_argument('-q', '--questions', required=True, help='Output file for questions only')

    # Evaluation
    parser_e = subparsers.add_parser('E', help='Evaluation')
    parser_e.add_argument('-M', '--mode', choices=['short', 'single'], required=True, help='Evaluation mode: short or single')
    parser_e.add_argument('-l', '--llm', required=True, help='llm')
    parser_e.add_argument('-o', '--output', required=True, help='Output log file for evaluation results')

    # Build Key
    parser_b = subparsers.add_parser('B', help='Build Key')
    parser_b.add_argument('-l', '--list', required=True, help='Input list file for building key')
    parser_b.add_argument('-o', '--output', required=True, help='Output file with keys')

    args = parser.parse_args()

    if args.command == 'K':
        print(f"Knowledge Extraction with list file: {args.input} and knowledge file: {args.output}")
        extactor = Knowledge(args.input, args.output)
        extactor.extract()
    elif args.command == 'Q':
        print(f"Question Generation with list file: {args.input}, output: {args.output}, question list: {args.questions}")
        generater = Question(args.input, args.output, args.questions)
        generater.generate()

        # convert single choice to open-ended questions
        # generater.convert_questions()
    elif args.command == 'E':
        print(f"Evaluation with mode: {args.mode}, LLM to evaluation: {args.llm}, output: {args.output}")
        envaluator = Envaluation('mistralai/mixtral-8x7b-instruct-v0.1', 'dataset/question_log_mix.json')
        if args.mode == 'single':
            envaluator.envaluate()
        elif args.mode == 'open':
            envaluator.envaluate_short_answer()
    elif args.command == 'B':
        print(f"Build Key with list: {args.list}, output: {args.output}")
        key_builder = BuildKey(args.list, args.output)
        key_builder.build()
    else:
        parser.print_help()

if __name__ == "__main__":

    # initialier = Buildinit('dataset/list.json', 'dataset/raw', 'dataset/data.json')
    # initialier.build()
    # initialier.draw_graph()

    # extactor = Knowledge('dataset/list.json', 'dataset/list_knwoledge.json')
    # extactor.extract()

    # generater = Question('dataset/list_knwoledge.json', 'dataset/list_knwoledge_question.json', 'dataset/question_log_mix.json')
    # # generater.generate()
    # generater.convert_questions()
    
    # envaluator = Envaluation('mistralai/mixtral-8x7b-instruct-v0.1', 'dataset/question_log_mix.json')
    # envaluator.envaluate_short_answer()

    # # print("correct rate:", correct_rate)
    # # print("incorrect rate:", incorrect_rate)
    # # print("undesired rate:", undesired_rate)
    # key_builder = BuildKey('dataset/list_knowledge.json', 'dataset/list_knwoledge_key.json')
    # key_builder.build()

    main()
