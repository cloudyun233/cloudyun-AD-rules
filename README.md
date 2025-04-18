# 自用广告过滤规则仓库 📦

## 简介 🎓

这是一名大学生在元旦节闲暇之余<button class="citation-flag" data-index="3">，由于家里小米路由器 `/data` 分区太小，无法直接放下几个广告过滤规则，所以编写的广告过滤规则仓库，主要供个人使用，适用于 ADguardHome 等 DNS 过滤工具。仓库中的规则源自多个上游规则，经过合并与去重检测后最终生成。🎯

**订阅链接**：  
📥 一键订阅规则：  

- **合并去重后的规则**：[beforeall.txt](https://raw.githubusercontent.com/cloudyun233/cloudyun-AD-rules/refs/heads/main/beforeall.txt)
- **检测后的有效规则**（可能有检测错误）：[all.txt](https://raw.githubusercontent.com/cloudyun233/cloudyun-AD-rules/refs/heads/main/all.txt)
- **精简版有效规则**（仅国内 DNS 解析成功）：[all-lite.txt](https://raw.githubusercontent.com/cloudyun233/cloudyun-AD-rules/refs/heads/main/all-lite.txt)
- **中国IP关联规则**（通过GeoIP2-CN数据库验证）：[all-cn.txt](https://raw.githubusercontent.com/cloudyun233/cloudyun-AD-rules/refs/heads/main/all-cn.txt)

## 上游规则简介 📚

本仓库的广告过滤规则来源于以下几个优质上游规则：

1. **[217heidai/adblockfilters](https://github.com/217heidai/adblockfilters)**  
   - **特点**：专为 AdGuard 设计的去广告规则，每 8 小时自动更新。  
   - **优势**：自动合并多个规则源，并移除无法解析的域名，确保规则的高效性和时效性。

2. **[privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD)**  
   - **特点**：中文区命中率最高的广告过滤列表，支持多种网络组件。  
   - **优势**：精准屏蔽广告和隐私追踪，兼容 AdGuardHome、dnsmasq 等工具。

3. **[hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists)**  
   - **特点**：专注于 DNS 层面的广告、恶意软件和跟踪保护。  
   - **优势**：提供多种过滤列表，涵盖广告、隐私保护和安全性需求。

## GeoIP2数据库简介 🌍

本仓库使用的中国IP关联规则验证数据库来自以下优质项目：

4. **[Hackl0us/GeoIP2-CN](https://github.com/Hackl0us/GeoIP2-CN)**  
   - **项目背景**：解决MaxMind的GeoLite2免费数据库存在的获取不便、数据量大、准确度低等问题。  
   - **项目优势**：  
     - **准确度高**：整合ipip.net和纯真IP数据库的中国大陆IP地址段信息  
     - **实用精悍**：数据库大小仅约100KB，加载时间短、查询效率高  
     - **CDN分发**：通过CDN全球分发，下载速度快  
     - **自动化更新**：每3天自动更新，无需人工干预  
   - **下载链接**：提供GitHub RAW和CDN加速两种下载方式  
   - **配置方式**：参考项目Wiki中的文档教程在各工具中自定义GeoIP2数据库

## 检测和域名处理说明 🔍

在生成最终的广告过滤规则文件 `all.txt` 和 `all-lite.txt` 之前，仓库中的规则会经过以下处理步骤：

1. **规则合并与去重**：  
   - 从多个上游规则源下载规则文件，合并所有规则并去除重复项，生成 `beforeall.txt` 文件。

2. **规则语法检查**：  
   - 对 `beforeall.txt` 中的每一行规则进行语法检查，确保规则格式正确。无效的规则将被过滤掉。

3. **域名有效性检测**：  
   - 从规则中提取域名，使用国内DNS服务器（`119.29.29.29`、`223.6.6.6`、`180.184.1.1`）和国外DNS服务器（`1.1.1.1`、`8.8.8.8`、`9.9.9.9`）进行解析。  
   - 去除无法解析的域名，确保最终规则中的域名都是有效的。

4. **生成最终规则文件**：  
   - 将有效的规则保存到 `all.txt` 文件中，包含所有通过国内或国外DNS解析成功的域名规则。
   - 生成 `all-lite.txt` 文件，仅包含通过国内DNS解析成功的域名规则，适用于对规则大小有严格限制的场景。
   - 生成 `all-cn.txt` 文件，仅包含通过GeoIP2-CN数据库验证与中国IP关联的域名规则，适用于只需过滤中国区域广告的场景。

## 自动化流程 ⚙️

本仓库使用 GitHub Actions 自动化流程来定期更新规则。具体流程如下：

1. **定时任务**：  
   - 每天 UTC 时间 20:00 自动运行，合并规则并生成新的 `beforeall.txt`、`all.txt` 和 `all-lite.txt` 文件。

2. **手动触发**：  
   - 支持通过 GitHub Actions 手动触发流程，方便随时更新规则。

3. **依赖安装**：  
   - 在自动化流程中，会安装必要的 Python 依赖，包括 `requests`、`loguru`、`dnspython`、`httpx`、`IPy`、`tld`、`pytz` 和 `geoip2`。
   - 下载 GeoIP2-CN 数据库用于验证域名是否与中国IP关联。

4. **规则处理**：  
   - 运行 `merge_rules.py` 脚本，下载并合并上游规则，生成 `beforeall.txt`。  
   - 运行 `dispose.py` 脚本，对 `beforeall.txt` 中的规则进行语法检查和域名有效性检测，生成最终的 `all.txt`、`all-lite.txt` 和 `all-cn.txt`。

5. **文件提交**：  
   - 将生成的 `beforeall.txt`、`all.txt`、`all-lite.txt`、`all-cn.txt`、`Country.mmdb` 和日志文件提交到 GitHub 仓库，并推送到 `main` 分支。

## 关于 GitHub 的使用和代码编写 💻

由于这是我第一次使用 GitHub，对相关操作完全不了解，全程依赖 AI 的帮助。从创建仓库、编写 README 文件，到合并规则和提交代码，每一步都是在 AI 的指导下完成的。🤖  
代码也全是 Deepseek 给出的，没有一点人工。倒是报错自己修了不少。🔧

---

**Happy Ad Blocking! 🎉**
