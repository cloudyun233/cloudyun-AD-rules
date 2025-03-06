# config_dnsmasq.py
# 存放dnsmasq规则源 URL 和其他配置

# dnsmasq规则源 URL 列表
SOURCE_URLS_DNSMASQ = [
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnsmasq.txt",
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/adblock-for-dnsmasq.conf",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/pro.txt",

    # 可以在这里添加更多源 URL
]

# 输出文件名
OUTPUT_FILE_DNSMASQ = "beforeall_dnsmasq.txt"

# 本地规则文件路径
LOCAL_RULE_FILE_DNSMASQ = "white_dnsmasq.txt"  # 本地dnsmasq规则文件路径