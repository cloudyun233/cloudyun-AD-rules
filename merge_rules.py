# merge_rules.py
# 主脚本，负责下载、合并和保存规则

import requests
import os
from datetime import datetime
from config import SOURCE_URLS, OUTPUT_FILE  # 从 config.py 导入配置

def download_rules(url):
    """从 URL 下载规则文件，返回规则列表"""
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.splitlines()
    else:
        raise Exception(f"Failed to download rules from {url}")

def merge_and_deduplicate_rules(rules_list):
    """合并并去重规则"""
    combined_rules = set()
    for rules in rules_list:
        combined_rules.update(rules)  # 使用集合去重
    return sorted(combined_rules)  # 返回排序后的规则列表

def save_rules_to_file(rules, filename):
    """将规则保存到文件"""
    with open(filename, 'w', encoding='utf-8') as file:
        for rule in rules:
            file.write(rule + '\n')

def print_file_line_count(filename, description):
    """输出文件的行数"""
    with open(filename, 'r', encoding='utf-8') as file:
        line_count = len(file.readlines())
    print(f"{description} 行数: {line_count}")

def main():
    try:
        # 下载所有源规则
        rules_list = []
        for url in SOURCE_URLS:
            rules = download_rules(url)
            rules_list.append(rules)
            print(f"已下载规则：{url}，行数: {len(rules)}")

        # 合并并去重
        merged_rules = merge_and_deduplicate_rules(rules_list)

        # 保存到文件
        save_rules_to_file(merged_rules, OUTPUT_FILE)

        # 输出结果文件的行数
        print_file_line_count(OUTPUT_FILE, f"{OUTPUT_FILE} 文件")
        print(f"规则已合并、去重，并保存到 {OUTPUT_FILE}")

        # 将文件推送到 GitHub Pages
        if os.getenv('GITHUB_ACTIONS'):  # 仅在 GitHub Actions 中运行
            os.system('git config --global user.name "GitHub Actions"')
            os.system('git config --global user.email "actions@github.com"')
            os.system(f'git add {OUTPUT_FILE}')
            os.system(f'git commit -m "Update {OUTPUT_FILE} - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}"')
            os.system('git push origin main')

    except Exception as e:
        print(f"发生错误：{e}")

if __name__ == "__main__":
    main()