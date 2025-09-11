const https = require('https');
const url = process.argv[2]; // 第一个参数是订阅 URL
const groupName = process.argv[3] || 'Proxy'; // 默认策略组名

if(!url) {
    console.error("请提供订阅 URL");
    process.exit(1);
}

// 下载远程规则
https.get(url, res => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
        const lines = data.split(/\r?\n/);
        const output = [];

        lines.forEach(line => {
            line = line.trim();
            if(!line || line.startsWith('#')) return;

            // DOMAIN 规则转换
            if(line.startsWith('DOMAIN,')) {
                const domain = line.split(',')[1];
                output.push(`DOMAIN-SUFFIX,${domain},${groupName}`);
            } 
            // DOMAIN-SUFFIX/KEYWORD 已是圈X可用格式直接保留
            else if(line.startsWith('DOMAIN-SUFFIX,') || line.startsWith('DOMAIN-KEYWORD,')) {
                output.push(`${line.split(',')[0]},${line.split(',')[1]},${groupName}`);
            }
            // IP-CIDR 可选
            else if(line.startsWith('IP-CIDR')) {
                output.push(`${line},${groupName}`);
            }
        });

        console.log('[Rule]');
        output.forEach(r => console.log(r));
    });
}).on('error', err => {
    console.error("下载规则失败:", err);
});
