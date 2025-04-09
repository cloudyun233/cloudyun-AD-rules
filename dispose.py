import os
import re
import asyncio
from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType
from datetime import datetime, timezone, timedelta
import geoip2.database

class RuleParser:
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.valid_rules = []  # 存储有效的规则
        self.domain_set = set()  # 存储提取的域名
        self.total_rules = 0  # 总规则数量
        self.valid_domains = set()  # 存储最终有效的域名 (A或AAAA解析成功)
        self.header_comments = []  # 存储开头的注释行
        self.has_header_been_collected = False  # 标记是否已经收集过注释行
        self.seen_comments = set()  # 用于存储已经出现过的注释行
        # --- Modified/New Attributes ---
        self.ipv4_set = set() # 存储所有解析成功的IPv4地址 (用于GeoIP查询)
        self.domain_to_ip_map = {} # 存储 域名 -> {ipv4_set} 的映射
        self.cn_domains = set() # 存储确定位于中国的域名
        # --- End Modified/New Attributes ---

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
        logger.info(f"解析完成，共找到{len(self.valid_rules)}条有效规则和{len(self.domain_set)}个唯一域名。")

    async def __resolve(self, dnsresolver, domain):
        """
        异步解析域名，获取IP地址（支持 A 和 AAAA 记录）。
        返回: (bool: 是否解析成功 A 或 AAAA, set: 解析到的IPv4地址集合)
        """
        resolved_ipv4s = set()
        is_valid = False
        try:
            # 尝试解析 A 记录（IPv4）
            query_object_a = await dnsresolver.resolve(qname=domain, rdtype="A")
            is_valid = True # A记录解析成功即认为域名有效
            for item in query_object_a.response.answer:
                if item.rdtype == DNSRdataType.A:
                    for rdata in item:
                        resolved_ipv4s.add(rdata.address) # 存储IPv4地址
        except Exception:
            pass # A记录解析失败或无记录

        if not is_valid: # 只有当A记录未解析成功时，才尝试AAAA记录来判断有效性
            try:
                # 尝试解析 AAAA 记录（IPv6）
                query_object_aaaa = await dnsresolver.resolve(qname=domain, rdtype="AAAA")
                for item in query_object_aaaa.response.answer:
                    if item.rdtype == DNSRdataType.AAAA:
                        is_valid = True # AAAA记录解析成功也认为域名有效
                        break # 找到一个AAAA即可
            except Exception:
                pass # AAAA记录解析失败或无记录

        return is_valid, resolved_ipv4s

    async def __pingx(self, dnsresolver, domain, semaphore):
        """
        异步检测域名的连通性。
        返回: (str: 域名, bool: 是否有效, set: IPv4地址集合)
        """
        async with semaphore:  # 限制并发数
            is_valid, resolved_ipv4s = await self.__resolve(dnsresolver, domain)
            return domain, is_valid, resolved_ipv4s

    async def __test_domains(self, domainList, nameservers, port=53):
        """
        测试域名列表中的域名，获取其有效性及IP地址。
        返回: (set: 有效域名集合, dict: {域名 -> {IPv4地址集合}}, set: 所有唯一IPv4地址集合)
        """
        logger.info(f"正在使用DNS服务器 {nameservers} 解析域名...")
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
        valid_domains_set = set()
        domain_to_ipv4_map = {}
        all_ipv4_set = set()
        completed_count = 0

        for future in asyncio.as_completed(taskList):
            domain, is_valid, resolved_ipv4s = await future
            completed_count += 1

            if is_valid:
                valid_domains_set.add(domain)
                if resolved_ipv4s: # 只有当解析到IPv4时才添加到map和set
                    domain_to_ipv4_map[domain] = resolved_ipv4s
                    all_ipv4_set.update(resolved_ipv4s)

            # 每完成 5000 个任务，输出一次进度
            if completed_count % 5000 == 0 or completed_count == total_domains:
                logger.info(f"已完成 {completed_count}/{total_domains} 个域名解析({completed_count / total_domains * 100:.2f}%)，使用DNS服务器: {nameservers}")

        logger.info(f"解析完成，共找到{len(valid_domains_set)}个有效域名和{len(all_ipv4_set)}个唯一IPv4地址，使用DNS服务器: {nameservers}。")
        return valid_domains_set, domain_to_ipv4_map, all_ipv4_set

    def filter_valid_rules(self):
        """过滤有效的规则, 并生成 all-lite.txt, all.txt, all-cn.txt"""
        # 国内和国外DNS服务器
        china_nameservers = ["119.29.29.29", "223.6.6.6", "180.184.1.1"]  # 国内DNS
        global_nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]  # 国外DNS

        # --- 1. 中国 DNS 解析 ---
        loop = asyncio.get_event_loop()
        china_valid_domains, china_domain_ip_map, china_ipv4s = loop.run_until_complete(
            self.__test_domains(self.domain_set, china_nameservers)
        )

        # --- 2. 生成 all-lite.txt 文件 ---
        lite_rules = []
        for rule in self.valid_rules:
            _, domain = self.__parse_line(rule)
            # 保留不需要域名解析的规则 或 国内 DNS 解析成功的域名对应的规则
            if domain is None or domain in china_valid_domains:
                lite_rules.append(rule)

        # 保存 all-lite.txt 文件
        lite_output_file = "all-lite.txt"
        self.save_rules_to_file(lite_rules, lite_output_file, "cloudyun-AD-rules-check-lite")
        logger.info(f"已保存{len(lite_rules)}条规则到文件 {lite_output_file}。")

        # --- 3. 国外 DNS 解析 (补充) ---
        unresolved_domains = self.domain_set - china_valid_domains
        global_valid_domains = set()
        global_domain_ip_map = {}
        global_ipv4s = set()
        if unresolved_domains:
            logger.info(f"正在尝试使用全球DNS解析{len(unresolved_domains)}个未解析域名...")
            global_valid_domains, global_domain_ip_map, global_ipv4s = loop.run_until_complete(
                self.__test_domains(unresolved_domains, global_nameservers)
            )
        else:
             logger.info("中国DNS检查后没有未解析的域名。")

        # --- 4. 合并结果 ---
        self.valid_domains = china_valid_domains.union(global_valid_domains)
        # Combine IP maps (global DNS results overwrite China DNS if domain exists in both)
        self.domain_to_ip_map = china_domain_ip_map.copy()
        self.domain_to_ip_map.update(global_domain_ip_map)
        # Combine all unique IPv4s found
        self.ipv4_set = china_ipv4s.union(global_ipv4s)

        logger.info(f"唯一有效域名总数(中国+全球DNS): {len(self.valid_domains)}")
        logger.info(f"发现的唯一IPv4地址总数: {len(self.ipv4_set)}")

        # --- 5. 准备 all.txt 的规则 ---
        all_txt_rules = []
        for rule in self.valid_rules:
            _, domain = self.__parse_line(rule)
            # 保留不需要域名解析的规则 或 所有解析成功的域名对应的规则
            if domain is None or domain in self.valid_domains:
                all_txt_rules.append(rule)
        logger.info(f"已筛选{len(all_txt_rules)}条规则用于all.txt文件。")

        # --- 6. GeoIP 判断 (使用修正后的逻辑) ---
        self.cn_domains = set() # Reset cn_domains before check
        if self.ipv4_set: # Only proceed if we have IPs to check
            logger.info("开始对关联域名进行GeoIP查询...")
            try:
                # Ensure the GeoLite2-Country.mmdb file exists
                geoip_db_path = 'Country.mmdb'
                if not os.path.exists(geoip_db_path):
                     logger.error(f"未找到GeoIP数据库文件: {geoip_db_path}，无法生成all-cn.txt文件。")
                else:
                    reader = geoip2.database.Reader(geoip_db_path)
                    processed_ips = 0
                    total_ips_to_check = len(self.ipv4_set)

                    # Iterate through the domain -> {ips} map
                    for domain, ips in self.domain_to_ip_map.items():
                        for ip in ips:
                            processed_ips += 1
                            try:
                                response = reader.country(ip)
                                if response.country.iso_code == 'CN':
                                    self.cn_domains.add(domain)
                                    # Log progress periodically
                                    # if processed_ips % 1000 == 0 or processed_ips == total_ips_to_check:
                                    #    logger.info(f"GeoIP check progress: {processed_ips}/{total_ips_to_check} IPs checked.")
                                    break # Found a CN IP for this domain, move to the next domain
                            except geoip2.errors.AddressNotFoundError:
                                # logger.warning(f"IP address not found in GeoIP database: {ip}")
                                pass # Ignore IPs not found in the database
                            except Exception as geo_e:
                                logger.error(f"GeoIP lookup error for IP {ip}: {geo_e}")
                                # Optionally break inner loop or handle differently
                        # Log progress after each domain if needed, or periodically based on IP count above

                    reader.close()
                    logger.info(f"GeoIP查询完成，共找到{len(self.cn_domains)}个与中国IP关联的域名。")

            except Exception as e:
                logger.error(f"Failed to load or use GeoIP database: {e}")
                # Ensure cn_domains is empty if GeoIP fails catastrophically
                self.cn_domains = set()

        else:
             logger.info("未找到可用于GeoIP查询的IPv4地址。")


        # --- 7. 生成 all-cn.txt 文件 (移到循环外部) ---
        if self.cn_domains or any(self.__parse_line(rule)[1] is None for rule in self.valid_rules): # Check if there are CN domains or rules without domains
             cn_rules = []
             for rule in self.valid_rules:
                 _, domain = self.__parse_line(rule)
                 # 保留不需要域名解析的规则 或 关联域名在 cn_domains 中的规则
                 if domain is None or domain in self.cn_domains:
                     cn_rules.append(rule)

             # 保存 all-cn.txt 文件
             if cn_rules: # Only save if there are rules to save
                 cn_output_file = "all-cn.txt"
                 self.save_rules_to_file(cn_rules, cn_output_file, "cloudyun-AD-rules-check-cn")
                 logger.info(f"已保存{len(cn_rules)}条规则到文件 {cn_output_file}。")
             else:
                 logger.info("没有符合all-cn.txt文件要求的规则。")
        else:
            logger.info("未发现位于中国的域名且无非域名规则，跳过all-cn.txt文件生成。")


        # --- 8. 返回 all.txt 的规则 ---
        return all_txt_rules


    def save_rules_to_file(self, rules, filename, title):
        """通用方法：保存规则列表到指定文件，包含标准头"""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                # 写入自定义前缀信息
                f.write(f"! Title: {title}\n")
                f.write(f"! Version: {self.get_beijing_time()}\n")  # 使用当前北京时间作为版本号
                f.write(f"! Homepage: https://github.com/cloudyun233/cloudyun-AD-rules\n")
                f.write(f"! Total lines: {len(rules)}\n")

                # 写入其他注释行（排除已写入的标准注释）
                standard_prefixes = ("! Title:", "! Version:", "! Homepage:", "! Total lines:")
                for comment in self.header_comments:
                    # Ensure comment is a string and check prefix
                    if isinstance(comment, str) and not comment.startswith(standard_prefixes):
                         f.write(comment + "\n")

                # 写入规则
                for line in rules:
                    f.write(line + "\n")
        except Exception as e:
             logger.error(f"保存规则到文件 {filename} 失败: {e}")


    def get_beijing_time(self):
        """获取当前北京时间"""
        try:
            utc_now = datetime.now(timezone.utc)  # 使用 timezone-aware 的 datetime 对象
            beijing_time = utc_now.astimezone(timezone(timedelta(hours=8)))
            return beijing_time.strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            logger.error(f"获取北京时间失败: {e}")
            # Fallback to UTC or a simple timestamp if needed
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')


    def print_statistics(self):
        """打印统计信息"""
        print("\n--- 统计信息 ---")
        print(f"读取的总规则数(不包括注释): {self.total_rules}")
        print(f"有效语法规则数: {len(self.valid_rules)}")
        print(f"提取的唯一域名数: {len(self.domain_set)}")
        print(f"解析成功的域名数(A或AAAA记录): {len(self.valid_domains)}")
        print(f"发现的唯一IPv4地址数: {len(self.ipv4_set)}")
        print(f"与中国IP关联的域名数: {len(self.cn_domains)}")
        print("--- 统计结束 ---")


if __name__ == "__main__":
    input_file = "beforeall.txt"  # 输入文件
    output_file = "all.txt"      # 主输出文件 (for all rules)

    # Setup logger
    logger.add("dispose.log", rotation="1 MB", level="INFO") # Log INFO and above to file

    logger.info("脚本开始运行。")
    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        logger.error(f"未找到输入文件: {input_file}")
        exit(1)

    # 解析规则并过滤
    parser = RuleParser(input_file, output_file)
    parser.parse_rules()

    # filter_valid_rules now handles generation of lite and cn files as side effects
    # and returns the rules for all.txt
    final_all_rules = parser.filter_valid_rules()

    # 打印统计信息
    parser.print_statistics()

    # 保存 all.txt 文件
    if final_all_rules:
        parser.save_rules_to_file(final_all_rules, output_file, "cloudyun-AD-rules-check") # Use the main output file name
        logger.info(f"已保存{len(final_all_rules)}条规则到主输出文件 {output_file}。")
    else:
        logger.warning(f"没有符合主输出文件 {output_file} 要求的规则。")

    logger.info("脚本运行完成。")