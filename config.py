# config.py
# 存放源 URL 和其他配置

# 源 URL 列表
SOURCE_URLS = [
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
    "https://anti-ad.net/easylist.txt",
    # "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt",

    # 可以在这里添加更多源 URL
]

# 输出文件名
OUTPUT_FILE = "beforeall.txt"

# 本地规则文件路径
LOCAL_RULE_FILE = "white.txt"  # 新增本地规则文件路径
