/**
 * Quantumult X 小火箭规则转换器
 * 功能：
 * 1. 抓取远程规则（支持小火箭/SSR规则集）
 * 2. 自动转换不兼容格式为圈X可识别格式
 * 3. 输出 QX 可导入规则列表
 */

const REMOTE_URL = "https://whatshub.top/rule/Google.list"; // 远程规则URL
const DEFAULT_PROXY = "Proxy"; // 默认策略组名

$task.fetch(REMOTE_URL).then(response => {
    const raw = response.body;

    const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));

    const rules = lines.map(line => {
        // 分隔符，小火箭规则可能有逗号或竖线
        let type, value;
        if (line.includes(',')) {
            [type, value] = line.split(',').map(s => s.trim());
        } else if (line.includes('|')) {
            [type, value] = line.split('|').map(s => s.trim());
        } else {
            // 仅一个值，默认为 DOMAIN-SUFFIX
            type = 'DOMAIN-SUFFIX';
            value = line;
        }

        if (!type || !value) return null;

        type = type.toUpperCase();

        // 转换规则类型
        switch(type){
            case 'DOMAIN-SUFFIX':
            case 'DOMAIN':
            case 'IP-CIDR':
            case 'GEOIP':
                return `${type},${value},${DEFAULT_PROXY}`;
            case 'DOMAIN-KEYWORD':
                // QX 不支持 DOMAIN-KEYWORD，转换成 REGEX
                // 转义特殊字符
                const escaped = value.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
                return `REGEX,${escaped},${DEFAULT_PROXY}`;
            case 'FINAL':
                // 小火箭可能写 FINAL,REJECT 或 FINAL,Proxy
                return `FINAL,DIRECT`;
            case 'IP-CIDR6':
                // IPv6 CIDR 转成 IP-CIDR（QX 也支持）
                return `IP-CIDR,${value},${DEFAULT_PROXY}`;
            case 'PROCESS-NAME':
                // QX 不支持，转换为注释
                return `# PROCESS-NAME,${value}`;
            case 'URL-REGEX':
            case 'REGEX':
                // 直接保留 REGEX
                return `REGEX,${value},${DEFAULT_PROXY}`;
            default:
                // 其他未知类型统一注释
                return `# ${type},${value}`;
        }
    }).filter(Boolean);

    const output = rules.join('\n');
    $done({ body: output });

}).catch(err => {
    $done({ body: `解析失败: ${err.message}` });
});
