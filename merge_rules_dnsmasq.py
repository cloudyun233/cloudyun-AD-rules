# merge_rules_dnsmasq.py
# 主脚本，负责下载、合并和保存dnsmasq格式的规则

import requests
import os
import re
from datetime import datetime, timezone, timedelta
from config_dnsmasq import SOURCE_URLS_DNSMASQ, OUTPUT_FILE_DNSMASQ, LOCAL_RULE_FILE_DNSMASQ  # 从 config_dnsmasq.py 导入配置

def download_rules(url):
    """从 URL 下载规则文件，返回规则列表和前缀信息"""
    response = requests.get(url)
    if response.status_code == 200:
        lines = response.text.splitlines()
        # 提取前缀信息（以 # 开头的行）
        prefix = [line for line in lines if line.startswith('#')]
        # 提取规则（不以 # 开头的行）
        rules = [line for line in lines if not line.startswith('#') and line.strip()]
        return prefix, rules
    else:
        raise Exception(f"Failed to download rules from {url}")

def load_local_rules(filepath):
    """从本地文件加载规则"""
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as file:
            lines = file.read().splitlines()
            # 提取前缀信息
            prefix = [line for line in lines if line.startswith('#')]
            # 提取规则
            rules = [line for line in lines if not line.startswith('#') and line.strip()]
            return prefix, rules
    else:
        print(f"本地规则文件 {filepath} 不存在，跳过加载。")
        return [], []

def normalize_dnsmasq_rule(rule):
    """标准化dnsmasq规则格式，统一为local=/domain/格式"""
    rule = rule.strip()
    
    # 处理address=/domain/ip格式
    if rule.startswith('address=/'):
        parts = rule.split('/')
        if len(parts) >= 3:
            domain = parts[1]
            return f"local=/{domain}/"
    
    # 处理local=/domain/格式
    elif rule.startswith('local=/'):
        parts = rule.split('/')
        if len(parts) >= 2:
            domain = parts[1]
            return f"local=/{domain}/"
    
    # 处理server=/domain/server格式
    elif rule.startswith('server=/'):
        parts = rule.split('/')
        if len(parts) >= 3:
            domain = parts[1]
            return f"local=/{domain}/"
            
    return rule

def merge_and_deduplicate_rules(rules_list):
    """合并并去重规则"""
    # 标准化所有规则
    normalized_rules = set()
    for rules in rules_list:
        for rule in rules:
            normalized_rule = normalize_dnsmasq_rule(rule)
            if normalized_rule:
                normalized_rules.add(normalized_rule)
    
    return sorted(normalized_rules)  # 返回排序后的规则列表

def get_beijing_time():
    """获取当前北京时间"""
    utc_now = datetime.now(timezone.utc)  # 使用 timezone-aware 的 datetime 对象
    beijing_time = utc_now.astimezone(timezone(timedelta(hours=8)))
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')

def save_rules_to_file(rules, filename):
    """将规则保存到文件"""
    with open(filename, 'w', encoding='utf-8') as file:
        # 写入自定义前缀信息
        file.write("# Title: cloudyun-AD-rules-dnsmasq\n")
        file.write(f"# Version: {get_beijing_time()}\n")  # 使用当前北京时间作为版本号
        file.write(f"# Homepage: https://github.com/cloudyun233/cloudyun-AD-rules\n")
        file.write(f"# Total lines: {len(rules)}\n")
        file.write("# 合并自多个上游规则源的dnsmasq格式广告过滤规则\n\n")
        # 写入规则
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
        for url in SOURCE_URLS_DNSMASQ:
            prefix, rules = download_rules(url)
            rules_list.append(rules)
            print(f"已下载规则：{url}，行数: {len(rules)}")

        # 加载本地规则
        local_prefix, local_rules = load_local_rules(LOCAL_RULE_FILE_DNSMASQ)
        if local_rules:
            rules_list.append(local_rules)
            print(f"已加载本地规则：{LOCAL_RULE_FILE_DNSMASQ}，行数: {len(local_rules)}")

        # 合并并去重
        merged_rules = merge_and_deduplicate_rules(rules_list)

        # 保存到文件
        save_rules_to_file(merged_rules, OUTPUT_FILE_DNSMASQ)

        # 输出结果文件的行数
        print_file_line_count(OUTPUT_FILE_DNSMASQ, f"{OUTPUT_FILE_DNSMASQ} 文件")
        print(f"规则已合并、去重，并保存到 {OUTPUT_FILE_DNSMASQ}")

    except Exception as e:
        print(f"发生错误：{e}")

if __name__ == "__main__":
    main()