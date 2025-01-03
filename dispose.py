import os
import re
import asyncio
from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType


class RuleParser:
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.valid_rules = []  # 存储有效的规则
        self.domain_set = set()  # 存储提取的域名
        self.total_rules = 0  # 总规则数量
        self.valid_domains = set()  # 存储有效的域名

    def __parse_line(self, line):
        """解析单行规则，提取域名"""
        line = line.strip()
        if not line or line.startswith("!"):  # 忽略空行和注释
            return line, None

        # 处理正则表达式规则
        if line.startswith("/") and line.endswith("/"):
            return line, None  # 保留正则表达式规则

        # 处理域名规则
        if line.startswith("@@||") and line.endswith("^"):  # 白名单规则
            domain = line[4:-1]  # 去掉 @@|| 和 ^
            return line, domain
        elif line.startswith("||") and line.endswith("^"):  # 黑名单规则
            domain = line[2:-1]  # 去掉 || 和 ^
            return line, domain
        elif re.match(r"^\S+\.\S+$", line):  # 简单域名规则
            return line, line
        return None, None  # 无效规则

    def parse_rules(self):
        """解析规则文件并提取域名"""
        try:
            with open(self.input_file, "r", encoding="utf-8") as f:
                for line in f:
                    self.total_rules += 1  # 统计总规则数量
                    rule, domain = self.__parse_line(line)
                    if rule is not None:  # 如果是有效规则
                        self.valid_rules.append(rule)
                        if domain:
                            self.domain_set.add(domain)
            logger.info(f"Parsed {len(self.valid_rules)} valid rules and {len(self.domain_set)} domains.")
        except Exception as e:
            logger.error(f"Error parsing rules: {e}")

    async def __resolve(self, dnsresolver, domain):
        """异步解析域名，获取IP地址"""
        try:
            query_object = await dnsresolver.resolve(qname=domain, rdtype="A")
            for item in query_object.response.answer:
                if item.rdtype == DNSRdataType.A:
                    return True  # 解析成功
        except Exception as e:
            pass  # 解析失败
        return False

    async def __pingx(self, dnsresolver, domain, semaphore):
        """异步检测域名的连通性"""
        async with semaphore:  # 限制并发数
            is_valid = await self.__resolve(dnsresolver, domain)
            return domain, is_valid

def __test_domains(self, domainList, nameservers, port=53):
    """测试域名列表中的域名，获取其IP地址"""
    logger.info("Resolving domains...")
    dnsresolver = DNSResolver()
    dnsresolver.nameservers = nameservers  # 设置DNS服务器
    dnsresolver.port = port

    loop = asyncio.get_event_loop()
    semaphore = asyncio.Semaphore(500)  # 限制并发量

    # 添加异步任务
    taskList = []
    total_domains = len(domainList)
    for index, domain in enumerate(domainList, 1):
        task = asyncio.ensure_future(self.__pingx(dnsresolver, domain, semaphore))
        taskList.append(task)

        # 每处理 5000 个域名，输出一次进度
        if index % 5000 == 0 or index == total_domains:
            logger.info(f"已处理 {index}/{total_domains} 个域名（{index / total_domains * 100:.2f}%）")

    # 等待所有任务完成
    loop.run_until_complete(asyncio.wait(taskList))

    # 获取任务结果
    valid_domains = {task.result()[0] for task in taskList if task.result()[1]}
    return valid_domains

    def filter_valid_rules(self):
        """过滤有效的规则"""
        try:
            # 使用国内和国外DNS服务器解析域名
            china_nameservers = ["114.114.114.114", "223.5.5.5", "119.29.29.29"]  # 国内DNS
            global_nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]  # 国外DNS

            # 解析域名
            valid_domains = self.__test_domains(self.domain_set, china_nameservers)
            valid_domains.update(self.__test_domains(self.domain_set, global_nameservers))
            self.valid_domains = valid_domains

            # 过滤有效规则
            filtered_rules = []
            for rule in self.valid_rules:
                _, domain = self.__parse_line(rule)
                if domain is None or domain in valid_domains:
                    filtered_rules.append(rule)

            logger.info(f"Filtered {len(filtered_rules)} valid rules.")
            return filtered_rules
        except Exception as e:
            logger.error(f"Error filtering rules: {e}")
            return []

    def save_rules(self, rules):
        """保存有效的规则到文件"""
        try:
            with open(self.output_file, "w", encoding="utf-8") as f:
                # 更新 Total lines
                for line in rules:
                    if line.startswith("! Total lines:"):
                        line = f"! Total lines: {len(rules)}\n"
                    f.write(line + "\n")
            logger.info(f"Saved {len(rules)} rules to {self.output_file}.")
        except Exception as e:
            logger.error(f"Error saving rules: {e}")

    def print_statistics(self):
        """打印统计信息"""
        print(f"检测规则数量: {self.total_rules}")
        print(f"有效规则数量: {len(self.valid_rules)}")
        print(f"检测域名数量: {len(self.domain_set)}")
        print(f"有效域名数量: {len(self.valid_domains)}")


if __name__ == "__main__":
    input_file = "beforeall.txt"  # 输入文件
    output_file = "all.txt"  # 输出文件

    # 解析规则并过滤
    parser = RuleParser(input_file, output_file)
    parser.parse_rules()
    valid_rules = parser.filter_valid_rules()

    # 打印统计信息
    parser.print_statistics()

    # 保存有效规则
    if valid_rules:
        parser.save_rules(valid_rules)