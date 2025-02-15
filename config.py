# config.py
# 存放源 URL 和其他配置

# 源 URL 列表
SOURCE_URLS = [
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt",

    # 可以在这里添加更多源 URL
]

# 输出文件名
OUTPUT_FILE = "beforeall.txt"

# 本地规则文件路径
LOCAL_RULE_FILE = "white.txt"  # 新增本地规则文件路径
