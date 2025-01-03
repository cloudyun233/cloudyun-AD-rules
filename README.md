# 自用广告过滤规则仓库 📦

## 简介 🎓

这是一名大学生在元旦节闲暇之余，由于家里小米路由器 `/data` 分区太小，无法直接放下几个广告过滤规则，所以编写的广告过滤规则仓库，主要供个人使用，适用于 ADguardHome 等 DNS 过滤工具。仓库中的规则源自多个上游规则，经过合并与去重处理后最终生成。🎯

**订阅链接**：  
📥 一键订阅所有规则：  
[https://raw.githubusercontent.com/cloudyun233/cloudyun-AD-rules/refs/heads/main/all.txt](https://raw.githubusercontent.com/cloudyun233/cloudyun-AD-rules/refs/heads/main/all.txt)

## 上游规则简介 📚

本仓库所使用的规则来源于以下几处上游规则：

1. **[217heidai/adblockfilters](https://github.com/217heidai/adblockfilters)**  
   适用于 AdGuard 的去广告合并规则，每 8 小时更新一次。该项目会定时自动获取各规则源更新，并生成合并规则库，还会去除已无法解析的域名。🔄

2. **[privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD)**  
   致力于成为中文区命中率最高的广告过滤列表，可实现精确的广告屏蔽和隐私保护。支持 AdGuardHome、dnsmasq 等多种网络组件，完全兼容常见广告过滤工具所支持的各种格式。🛡️

3. **[8680/GOODBYEADS](https://github.com/8680/GOODBYEADS)**  
   适用于 AdGuard、Qx 的去广告规则，会合并优质上游规则并进行去重整理排列。👋

4. **[afwfv/DD-AD](https://github.com/afwfv/DD-AD)**  
   将广告过滤规则进行整合，提供了适用于不同工具的多种规则文件，还针对番茄小说、七猫小说广告添加了规则。📖

## 检测和域名处理说明 🔍

在生成最终的广告过滤规则文件 `all.txt` 之前，仓库中的规则会经过以下处理步骤：

1. **规则合并与去重**：
   - 从多个上游规则源下载规则文件，合并所有规则并去除重复项，生成 `beforeall.txt` 文件。

2. **规则语法检查**：
   - 对 `beforeall.txt` 中的每一行规则进行语法检查，确保规则格式正确。无效的规则将被过滤掉。

3. **域名有效性检测**：
   - 从规则中提取域名，使用国内和国外 DNS 服务器（如 `114.114.114.114` 和 `8.8.8.8`）进行解析。
   - 去除无法解析的域名，确保最终规则中的域名都是有效的。

4. **生成最终规则文件**：
   - 将有效的规则保存到 `all.txt` 文件中，并更新 `! Total lines:` 为有效规则的总数。

通过以上步骤，确保生成的广告过滤规则文件 `all.txt` 中的规则都是语法正确且域名有效的。

## 关于 GitHub 的使用和代码编写 💻

由于这是我第一次使用 GitHub，对相关操作完全不了解，全程依赖 AI 的帮助。从创建仓库、编写 README 文件，到合并规则和提交代码，每一步都是在 AI 的指导下完成的。🤖  
代码也全是 Deepseek 给出的，没有一点人工。倒是报错自己修了不少。🔧

---

**Happy Ad Blocking! 🎉**
