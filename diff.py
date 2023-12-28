import json
import re
import os
import requests
from bs4 import BeautifulSoup
import numpy as np


def find_function(soup, lang):
    li = []
    # python源码
    if 'py' == lang:
        # 使用正则表达式查找包含 @@ def 关键字的标签
        pattern_Py = re.compile(r'@@ def')
        function_all = soup.find_all(lambda tag: tag.name == 'td' and pattern_Py.search(tag.text))

        for function in function_all:
            functionName = function.text.split('@@ def ')[1].split('(')[0]
            fileName_func = function.find_previous('span', class_="Truncate").text.strip()
            funcPath = fileName_func + ':' + functionName
            li.append(funcPath)
    # c++源码
    elif 'c/c++' == lang:
        pattern_Cpp = re.compile(r'\b\w+\s+(\w+)\s*\([^)]*\)\s*;')
        function_all = soup.find_all(lambda tag: tag.name == 'td' and pattern_Cpp.search(tag.text))

        for function in function_all:
            match = re.match(pattern_Cpp, function.text.strip())
            functionName = match.group(1)
            print(functionName)
            print(functionName)
            fileName_func = function.find_previous('span', class_="Truncate").text.strip()
            funcPath = fileName_func + ':' + functionName
            li.append(funcPath)

    else:
        return 'unsupported language'
    return li


def find_addition(soup):
    addList = []
    additions = soup.find_all('td', class_=lambda value: value and 'blob-code-addition' in value)
    print("\n------------------------------------Additions are as follows------------------------------------")
    for addition in additions:
        # 新增的函数不可能是漏洞函数，故不做内容检测
        additionText = addition.text.strip()
        lineNum_add = addition.find_previous('td')['data-line-number'].strip()
        fileName_add = addition.find_previous('span', class_="Truncate").text.strip()
        print(f'line{lineNum_add} in {fileName_add}: {additionText}')
        addList.append(additionText)
    return addList


def get_commit_diff(url, owner, repo, code, commit_sha):
    url = f'https://github.com/{owner}/{repo}/pull/{code}/commits/{commit_sha}'
    print(url)
    response = requests.get(url, verify=False)
    deleteList = []
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        additions = find_addition(soup)
        deletions = soup.find_all('td', class_=lambda value: value and 'blob-code-deletion' in value)
        file_struc = soup.find_all('span', class_='Truncate')
        for i in range(len(file_struc)):
            if '.py' in file_struc[i].text.strip():
                lang = 'py'
                break
            elif '.h' in file_struc[i].text.strip() or '.cpp' in file_struc[i].text.strip() or '.c' in file_struc[
                i].text.strip():
                lang = 'c/c++'
                break
            else:
                lang = 'unknown'

        funcList = find_function(soup, lang)

        print("\n------------------------------------Deletions are as follows------------------------------------")
        for deletion in deletions:
            deletionText = deletion.text.strip()
            # 因为删除的函数可能是漏洞函数，所以对删除部分逐行判断
            preTd = deletion.find_previous('td')
            lineNum_del = preTd.find_previous('td')['data-line-number'].strip()
            fileName_del = deletion.find_previous('span', class_="Truncate").text.strip()
            print(f'line{lineNum_del} in {fileName_del}: {deletionText}')
            deleteList.append(deletionText)
            # if 'py' in lang:
            #     # 匹配 Python 函数声明的正则表达式
            #     pattern = r'\bdef\s+\w+\s*\([^)]*\)\s*:'
            #     if re.search(pattern, deletionText):
            #         functionName = deletionText.split('def ')[1].split('(')[0]
            #         funcPath = fileName_del + ':' + functionName
            #         funcList.append(funcPath)
            # elif 'c++' in lang:
            #     # 正则表达式模式，使用捕获组
            #     pattern_cFunc = re.compile(r'\b(\w+)\s+\w+\s*\([^)]*\)\s*;')
            #     match = re.match(pattern_cFunc, deletionText)
            #     if match:
            #         functionName = match.group(1)
            #         funcPath = fileName_del + ':' + functionName
            #         funcList.append(funcPath)
        if len(funcList) == 0:
            funcList.append('No functions affected!')

        function_dic = {
            'url': url,
            'affected_functions': list(set(funcList))
        }
        return function_dic
    else:
        print('request failed!!')


if __name__ == "__main__":
    # owner = 'dpgaspar'
    # repo = 'Flask-AppBuilder'
    # code = '1804'
    # commit_sha = '5214d975ebad2ff32057443d2cc20fef1c04d0ea'
    #
    # # owner = 'esphome'
    # # repo = 'esphome'
    # # code = '2409'
    # # commit_sha = '207cde1667d8c799a197b78ca8a5a14de8d5ca1e'
    #
    # funcList = set(get_commit_diff(owner, repo, code, commit_sha))
    # print("------------------------------------Affected functions------------------------------------")
    # for func in funcList:
    #     print(func)

    folder_path = "CommitsLists"
    file_name = "commitlist.txt"
    file_path = os.path.join(folder_path, file_name)
    results = []
    # 检查文件是否存在
    if os.path.exists(file_path):
        # 打开文件并逐行解析数据
        with open(file_path, 'r') as file:
            for line in file:
                url = line
                line = line.strip().split('/')
                # 筛选有效url
                if 'pull' not in line:
                    continue
                # 匹配SHA加密后的数据
                sha_pattern = re.compile(r'\b[0-9a-f]{40}\b', re.I)
                match = sha_pattern.search(url)
                if match:
                    owner = line[-6]
                    repo = line[-5]
                    code = line[-3]
                    commit_sha = line[-1].split('?')[0]
                    functions = get_commit_diff(url, owner, repo, code, commit_sha)
                    results.append(functions)
                else:
                    print('url不合法')
                    continue

    else:
        print(f"The file {file_path} does not exist.")
    print("------------------------Results------------------------")
    # 将字典列表转换为 JSON 格式的字符串列表
    json_results = [json.dumps(result) for result in results]
    with open('result.txt', 'w') as f:
        for json_re in json_results:
            print(json_re)
            f.write(json_re + '\n')
