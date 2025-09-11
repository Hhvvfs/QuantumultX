import requests
import re

# 配置
URL = "https://whatshub.top/rule/Google.list"
OUTPUT_FILE = "output_rules.conf"
DEFAULT_POLICY = "PROXY"  # Quantumult X 策略组名，如 "PROXY"、"DIRECT"、"REJECT"

def download_rules(url):
    """从 URL 下载规则内容"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text.strip().splitlines()
    except Exception as e:
        print(f"下载失败: {e}")
        return []

def parse_line_to_quantumult_rule(line):
    """解析单行规则到 Quantumult X 格式
    输入格式假设：
    - 纯域名: example.com → HOST-SUFFIX,example.com,PROXY
    - AdBlock 风格: ||example.com^ → HOST-SUFFIX,example.com,PROXY
    - IP-CIDR: 192.168.1.0/24 → IP-CIDR,192.168.1.0/24,PROXY
    """
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('//'):  # 跳过注释
        return None
    
    # 清理 AdBlock/Surge 风格: ||domain^ → domain
    line = re.sub(r'^\|\|', '', line)  # 移除 ||
    line = re.sub(r'\^$', '', line)    # 移除 ^
    
    # 检查是否为 IP-CIDR
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', line):
        if '/' not in line:
            line += '/32'  # 单 IP 默认 /32
        return f"IP-CIDR,{line},{DEFAULT_POLICY}"
    
    # 域名处理：优先 HOST-SUFFIX（匹配子域名）
    if '.' in line:
        return f"HOST-SUFFIX,{line},{DEFAULT_POLICY}"
    
    return None

def main():
    lines = download_rules(URL)
    if not lines:
        print("无规则内容，退出。")
        return
    
    quantumult_rules = []
    for i, line in enumerate(lines, 1):
        rule = parse_line_to_quantumult_rule(line)
        if rule:
            quantumult_rules.append(rule)
        if i % 100 == 0:  # 进度提示
            print(f"已处理 {i} 行...")
    
    # 写入 Quantumult X 规则文件（纯文本格式）
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("# Quantumult X Rules generated from Google.list\n")
        for rule in quantumult_rules:
            f.write(f"{rule}\n")
    
    print(f"转换完成！输出文件: {OUTPUT_FILE}")
    print(f"总规则数: {len(quantumult_rules)}")
    print("示例规则（前5条）:")
    for rule in quantumult_rules[:5]:
        print(f"- {rule}")

if __name__ == "__main__":
    main()
