import os
import re
import asyncio
import time
from collections import defaultdict
from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType
from dns.exception import DNSException

class RuleParser:
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.valid_rules = []  # 存储有效的规则
        self.domain_set = set()  # 存储提取的域名
        self.domain_to_rules = defaultdict(list)  # 存储域名到规则的映射
        self.parent_domains = set()  # 存储父域名
        self.domain_hierarchy = defaultdict(set)  # 存储域名层级关系
        self.total_rules = 0  # 总规则数量
        self.valid_domains = set()  # 存储有效的域名
        self.header_comments = []  # 存储开头的注释行
        self.has_header_been_collected = False  # 标记是否已经收集过注释行
        self.seen_comments = set()  # 用于存储已经出现过的注释行
        self.dns_cache = {}  # DNS查询结果缓存

    def __parse_line(self, line):
        """解析单行规则，提取域名"""
        line = line.strip()
        if not line or line.startswith("#"):  # 忽略空行和以 # 开头的注释
            return line, None

        # 处理正则表达式规则
        if line.startswith("/") and line.endswith("/"):
            return line, None  # 保留正则表达式规则

        # 处理包含 * 的规则
        if "*" in line:
            return line, None  # 保留包含 * 的规则

        # 处理域名规则
        if line.startswith("@@||") and line.endswith("^"):  # 白名单规则
            domain = line[4:-1]  # 去掉 @@|| 和 ^
            return line, domain
        elif line.startswith("@@||") and line.endswith("^$important"):  # 重要白名单规则
            domain = line[4:-11]
            return line, domain
        elif line.startswith("||") and line.endswith("^"):  # 黑名单规则
            domain = line[2:-1]  # 去掉 || 和 ^
            return line, domain
        elif re.match(r"^\S+\s+\S+$", line):  # 简单域名规则（假设格式为 IP 地址 + 域名）
            parts = line.split(None, 1)
            domain = parts[1]
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
                            self.domain_to_rules[domain].append(rule)
        
        # 分析域名层级关系
        self.__analyze_domain_hierarchy()
        
        logger.info(f"Parsed {len(self.valid_rules)} valid rules and {len(self.domain_set)} domains.")
        logger.info(f"Identified {len(self.parent_domains)} parent domains for DNS resolution.")
    
    def __analyze_domain_hierarchy(self):
        """分析域名层级关系，识别父域名和子域名"""
        # 构建域名层级关系
        for domain in self.domain_set:
            parts = domain.split('.')
            # 从二级域名开始构建父域名
            if len(parts) >= 2:
                parent = '.'.join(parts[-2:])
                self.parent_domains.add(parent)
                self.domain_hierarchy[parent].add(domain)
                
                # 对于更长的域名，继续构建中间层级
                for i in range(3, min(len(parts) + 1, 5)):  # 限制层级深度，避免过度分析
                    mid_domain = '.'.join(parts[-i:])
                    self.domain_hierarchy[parent].add(mid_domain)
            else:
                # 对于顶级域名，直接添加到父域名集合
                self.parent_domains.add(domain)

    async def __resolve(self, dnsresolver, domain):
        """异步解析域名，获取IP地址（支持 A 和 AAAA 记录）"""
        # 检查缓存，但只有当缓存结果为True时才使用缓存
        # 这样可以确保解析失败的域名在不同DNS服务器间能重新尝试解析
        if domain in self.dns_cache and self.dns_cache[domain] is True:
            return True
            
        try:
            # 尝试解析 A 记录（IPv4）
            try:
                query_object_a = await dnsresolver.resolve(qname=domain, rdtype="A")
                for item in query_object_a.response.answer:
                    if item.rdtype == DNSRdataType.A:
                        self.dns_cache[domain] = True
                        return True  # 解析成功
            except DNSException:
                pass  # 继续尝试AAAA记录

            # 尝试解析 AAAA 记录（IPv6）
            try:
                query_object_aaaa = await dnsresolver.resolve(qname=domain, rdtype="AAAA")
                for item in query_object_aaaa.response.answer:
                    if item.rdtype == DNSRdataType.AAAA:
                        self.dns_cache[domain] = True
                        return True  # 解析成功
            except DNSException:
                pass
                
        except Exception as e:
            logger.debug(f"解析域名 {domain} 时出错: {str(e)}")
            
        # 不再缓存失败结果，让每个DNS服务器都有机会尝试解析
        return False

    async def __pingx(self, dnsresolver, domain, semaphore):
        """异步检测域名的连通性"""
        async with semaphore:  # 限制并发数
            is_valid = await self.__resolve(dnsresolver, domain)
            return domain, is_valid

    async def __test_domains(self, domainList, nameservers, port=53, max_concurrency=500):
        """测试域名列表中的域名，获取其IP地址"""
        start_time = time.time()
        logger.info(f"开始解析 {len(domainList)} 个域名...")
        
        # 创建DNS解析器
        dnsresolver = DNSResolver()
        dnsresolver.nameservers = nameservers  # 设置DNS服务器
        dnsresolver.port = port
        dnsresolver.lifetime = 3.0  # 设置超时时间，避免单个查询阻塞太久

        # 动态调整并发量，根据域名数量设置合理的并发数
        concurrency = min(max_concurrency, len(domainList))
        semaphore = asyncio.Semaphore(concurrency)
        logger.info(f"设置DNS查询并发数为: {concurrency}")

        # 添加异步任务
        taskList = []
        total_domains = len(domainList)
        for domain in domainList:
            task = asyncio.ensure_future(self.__pingx(dnsresolver, domain, semaphore))
            taskList.append(task)

        # 监控任务完成进度
        valid_domains = set()
        completed_count = 0
        progress_interval = max(1, min(5000, total_domains // 10))  # 动态调整进度报告间隔
        
        for future in asyncio.as_completed(taskList):
            try:
                domain, is_valid = await future
                completed_count += 1

                if is_valid:
                    valid_domains.add(domain)
                    # 如果是父域名解析成功，将其所有子域名也标记为有效
                    if domain in self.domain_hierarchy:
                        for child_domain in self.domain_hierarchy[domain]:
                            valid_domains.add(child_domain)

                # 动态报告进度
                if completed_count % progress_interval == 0 or completed_count == total_domains:
                    elapsed = time.time() - start_time
                    rate = completed_count / elapsed if elapsed > 0 else 0
                    remaining = (total_domains - completed_count) / rate if rate > 0 else 0
                    logger.info(f"已解析 {completed_count}/{total_domains} 个域名 ({completed_count/total_domains*100:.2f}%) - 速率: {rate:.1f}域名/秒, 预计剩余时间: {remaining/60:.1f}分钟")
            except Exception as e:
                logger.error(f"处理域名解析结果时出错: {str(e)}")
                completed_count += 1

        elapsed = time.time() - start_time
        logger.info(f"域名解析完成，耗时 {elapsed:.2f} 秒，有效域名数量: {len(valid_domains)}")
        return valid_domains

    def filter_valid_rules(self):
        """过滤有效的规则"""
        # 国内和国外DNS服务器
        china_nameservers = ["119.29.29.29", "223.6.6.6", "180.184.1.1", "114.114.114.114", "1.2.4.8"]  # 国内DNS
        global_nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]  # 国外DNS

        # 解析域名 - 只解析父域名而不是所有域名
        loop = asyncio.get_event_loop()
        logger.info(f"使用父域名策略，将解析 {len(self.parent_domains)} 个域名而不是 {len(self.domain_set)} 个域名")
        china_valid_domains = loop.run_until_complete(self.__test_domains(self.parent_domains, china_nameservers))

        # 生成 all-lite.txt 文件，仅包含国内 DNS 解析成功的域名
        lite_rules = []
        for rule in self.valid_rules:
            _, domain = self.__parse_line(rule)
            if domain is None or domain in china_valid_domains:  # 保留不需要域名解析的规则或国内 DNS 解析成功的域名
                lite_rules.append(rule)

        # 保存 all-lite.txt 文件
        lite_output_file = "all-lite.txt"
        with open(lite_output_file, "w", encoding="utf-8") as f:
            # 写入注释行
            seen_titles = set()  # 用于记录已经写入的 Title 和 Total lines
            for comment in self.header_comments:
                if comment.startswith("! Title:"):
                    if "! Title:" not in seen_titles:  # 确保只写入一次 Title
                        f.write("! Title: cloudyun-check-lite\n")
                        seen_titles.add("! Title:")
                elif comment.startswith("! Total lines:"):
                    if "! Total lines:" not in seen_titles:  # 确保只写入一次 Total lines
                        f.write(f"! Total lines: {len(lite_rules)}\n")
                        seen_titles.add("! Total lines:")
                else:
                    f.write(comment + "\n")  # 其他注释行保持不变
            # 写入过滤后的规则
            for line in lite_rules:
                f.write(line + "\n")
        logger.info(f"Saved {len(lite_rules)} rules to {lite_output_file}.")

        # 继续生成 all.txt 文件
        unresolved_domains = self.parent_domains - china_valid_domains
        if unresolved_domains:
            logger.info(f"开始使用国外DNS解析未成功的 {len(unresolved_domains)} 个父域名...")
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
            # 写入注释行
            seen_titles = set()  # 用于记录已经写入的 Title 和 Total lines
            for comment in self.header_comments:
                if comment.startswith("! Title:"):
                    if "! Title:" not in seen_titles:  # 确保只写入一次 Title
                        f.write("! Title: cloudyun-AD-rules-check\n")
                        seen_titles.add("! Title:")
                elif comment.startswith("! Total lines:"):
                    if "! Total lines:" not in seen_titles:  # 确保只写入一次 Total lines
                        f.write(f"! Total lines: {len(rules)}\n")
                        seen_titles.add("! Total lines:")
                else:
                    f.write(comment + "\n")  # 其他注释行保持不变
            # 写入过滤后的规则
            for line in rules:
                f.write(line + "\n")
        logger.info(f"Saved {len(rules)} rules to {self.output_file}.")

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
