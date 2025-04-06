# dispose.py 用于进一步检测规则文件，并输出有效规则和有效域名。

import os
import re
import asyncio
from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType
from datetime import datetime, timezone, timedelta

class RuleParser:
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.valid_rules = []  # 存储有效的规则
        self.domain_set = set()  # 存储提取的域名
        self.total_rules = 0  # 总规则数量
        self.valid_domains = set()  # 存储有效的域名
        self.header_comments = []  # 存储开头的注释行
        self.has_header_been_collected = False  # 标记是否已经收集过注释行
        self.seen_comments = set()  # 用于存储已经出现过的注释行

    def __parse_line(self, line):
        """解析单行规则，提取域名"""
        line = line.strip()
        if not line or line.startswith("!"):  # 忽略空行和以 ! 开头的注释
            return line, None

        # 处理正则表达式规则
        if line.startswith("/"):
            return line, None  # 保留正则表达式规则

        # 处理域名规则
        if line.startswith("@@||"):  # 白名单规则
            if line.endswith("^"):  # 标准白名单规则
                domain = line[4:-1]  # 去掉 @@|| 和 ^
                return line, domain
            elif line.endswith("^$important"):  # 重要白名单规则
                domain = line[4:-11]  # 去掉 @@|| 和 ^$important
                return line, domain
            else:  # 不带选项且不以^结尾的白名单规则
                domain = line[4:]  # 只去掉 @@||
                return line, domain
        elif line.startswith("||"):  # 黑名单规则
            if line.endswith("^"):  # 标准黑名单规则
                domain = line[2:-1]  # 去掉 || 和 ^
                return line, domain
            else:  # 不带选项且不以^结尾的黑名单规则
                domain = line[2:]  # 只去掉 ||
                return line, domain
        return None, None  # 无效规则

    def parse_rules(self):
        """解析规则文件并提取域名"""
        with open(self.input_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("!") and not self.has_header_been_collected:  # 只收集一次注释行
                    stripped_line = line.strip()
                    if stripped_line not in self.seen_comments:  # 去重逻辑
                        self.header_comments.append(stripped_line)
                        self.seen_comments.add(stripped_line)
                elif not line.startswith("!"):  # 非注释行
                    self.has_header_been_collected = True  # 标记已收集注释行
                    self.total_rules += 1  # 统计总规则数量
                    rule, domain = self.__parse_line(line)
                    if rule is not None:  # 如果是有效规则
                        self.valid_rules.append(rule)
                        if domain:
                            self.domain_set.add(domain)
        logger.info(f"Parsed {len(self.valid_rules)} valid rules and {len(self.domain_set)} domains.")

    async def __resolve(self, dnsresolver, domain):
        """异步解析域名，获取IP地址（支持 A 和 AAAA 记录）"""
        try:
            # 尝试解析 A 记录（IPv4）
            query_object_a = await dnsresolver.resolve(qname=domain, rdtype="A")
            for item in query_object_a.response.answer:
                if item.rdtype == DNSRdataType.A:
                    return True  # 解析成功

            # 尝试解析 AAAA 记录（IPv6）
            query_object_aaaa = await dnsresolver.resolve(qname=domain, rdtype="AAAA")
            for item in query_object_aaaa.response.answer:
                if item.rdtype == DNSRdataType.AAAA:
                    return True  # 解析成功
        except Exception:
            pass  # 解析失败
        return False

    async def __pingx(self, dnsresolver, domain, semaphore):
        """异步检测域名的连通性"""
        async with semaphore:  # 限制并发数
            is_valid = await self.__resolve(dnsresolver, domain)
            return domain, is_valid

    async def __test_domains(self, domainList, nameservers, port=53):
        """测试域名列表中的域名，获取其IP地址"""
        logger.info("Resolving domains...")
        dnsresolver = DNSResolver()
        dnsresolver.nameservers = nameservers  # 设置DNS服务器
        dnsresolver.port = port

        semaphore = asyncio.Semaphore(500)  # 限制并发量为 500

        # 添加异步任务
        taskList = []
        total_domains = len(domainList)
        for domain in domainList:
            task = asyncio.ensure_future(self.__pingx(dnsresolver, domain, semaphore))
            taskList.append(task)

        # 监控任务完成进度
        valid_domains = set()
        completed_count = 0
        for future in asyncio.as_completed(taskList):
            domain, is_valid = await future
            completed_count += 1

            if is_valid:
                valid_domains.add(domain)

            # 每完成 5000 个任务，输出一次进度
            if completed_count % 5000 == 0 or completed_count == total_domains:
                logger.info(f"已解析 {completed_count}/{total_domains} 个域名（{completed_count / total_domains * 100:.2f}%）")

        return valid_domains

    def filter_valid_rules(self):
        """过滤有效的规则"""
        # 国内和国外DNS服务器
        china_nameservers = ["119.29.29.29", "223.6.6.6", "180.184.1.1"]  # 国内DNS
        global_nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]  # 国外DNS

        # 解析域名
        loop = asyncio.get_event_loop()
        china_valid_domains = loop.run_until_complete(self.__test_domains(self.domain_set, china_nameservers))

        # 生成 all-lite.txt 文件，仅包含国内 DNS 解析成功的域名
        lite_rules = []
        for rule in self.valid_rules:
            _, domain = self.__parse_line(rule)
            if domain is None or domain in china_valid_domains:  # 保留不需要域名解析的规则或国内 DNS 解析成功的域名
                lite_rules.append(rule)

        # 保存 all-lite.txt 文件
        lite_output_file = "all-lite.txt"
        with open(lite_output_file, "w", encoding="utf-8") as f:
            # 写入自定义前缀信息
            f.write("! Title: cloudyun-AD-rules-check-lite\n")
            f.write(f"! Version: {self.get_beijing_time()}\n")  # 使用当前北京时间作为版本号
            f.write(f"! Homepage: https://github.com/cloudyun233/cloudyun-AD-rules\n")
            f.write(f"! Total lines: {len(lite_rules)}\n")
            
            # 写入其他注释行（排除已写入的标准注释）
            for comment in self.header_comments:
                if not (comment.startswith("! Title:") or 
                        comment.startswith("! Version:") or 
                        comment.startswith("! Homepage:") or 
                        comment.startswith("! Total lines:")):
                    f.write(comment + "\n")
                    
            # 写入过滤后的规则
            for line in lite_rules:
                f.write(line + "\n")
        logger.info(f"Saved {len(lite_rules)} rules to {lite_output_file}.")

        # 继续生成 all.txt 文件
        unresolved_domains = self.domain_set - china_valid_domains
        if unresolved_domains:
            logger.info(f"开始解析未成功的 {len(unresolved_domains)} 个域名...")
            global_valid_domains = loop.run_until_complete(self.__test_domains(unresolved_domains, global_nameservers))
            china_valid_domains.update(global_valid_domains)

        self.valid_domains = china_valid_domains

        # 过滤有效规则
        filtered_rules = []
        for rule in self.valid_rules:
            _, domain = self.__parse_line(rule)
            if domain is None or domain in china_valid_domains:  # 保留不需要域名解析的规则
                filtered_rules.append(rule)

        logger.info(f"Filtered {len(filtered_rules)} valid rules.")
        return filtered_rules

    def save_rules(self, rules):
        """保存有效的规则到文件"""
        with open(self.output_file, "w", encoding="utf-8") as f:
            # 写入自定义前缀信息
            f.write("! Title: cloudyun-AD-rules-check\n")
            f.write(f"! Version: {self.get_beijing_time()}\n")  # 使用当前北京时间作为版本号
            f.write(f"! Homepage: https://github.com/cloudyun233/cloudyun-AD-rules\n")
            f.write(f"! Total lines: {len(rules)}\n")
            
            # 写入其他注释行（排除已写入的标准注释）
            for comment in self.header_comments:
                if not (comment.startswith("! Title:") or 
                        comment.startswith("! Version:") or 
                        comment.startswith("! Homepage:") or 
                        comment.startswith("! Total lines:")):
                    f.write(comment + "\n")
                    
            # 写入过滤后的规则
            for line in rules:
                f.write(line + "\n")
        logger.info(f"Saved {len(rules)} rules to {self.output_file}.")

    def get_beijing_time(self):
        """获取当前北京时间"""
        utc_now = datetime.now(timezone.utc)  # 使用 timezone-aware 的 datetime 对象
        beijing_time = utc_now.astimezone(timezone(timedelta(hours=8)))
        return beijing_time.strftime('%Y-%m-%d %H:%M:%S')
        
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
