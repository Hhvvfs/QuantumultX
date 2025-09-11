/**
 * @supported_version 1.0
 * @name Multi-Subscription Parser
 * @description 通用圈X解析器，支持多远程订阅，自动转换圈X规则格式，添加品牌标记
 * @update_url https://your-server.com/resource-parser.js
 */

const subscriptionsUrl = "https://your-server.com/subscriptions.json"; // 订阅列表 JSON

// 圈X 提供的异步 HTTP 客户端
async function fetchJson(url) {
    try {
        const resp = await $httpClient.get(url);
        return JSON.parse(resp.body);
    } catch (e) {
        console.log("抓取订阅列表失败:", e);
        return [];
    }
}

async function fetchRules(sub) {
    try {
        const resp = await $httpClient.get(sub.url);
        if (!resp || !resp.body) return [];

        const lines = resp.body.split(/\r?\n/);
        const result = [];

        const typeMap = {
            "DOMAIN-KEYWORD": "HOST-KEYWORD",
            "IP-CIDR": "IP-CIDR",
            "USER-AGENT": "USER-AGENT"
        };

        for (const line of lines) {
            const trimLine = line.trim();
            if (!trimLine || trimLine.startsWith("#")) continue;
            const parts = trimLine.split(",");
            const ruleType = parts[0].trim();
            if (!typeMap[ruleType]) continue;

            let content = parts[1].trim();
            if ((ruleType === "IP-CIDR") && parts[2] && parts[2].trim() === "no-resolve") {
                // 去掉 no-resolve
            }

            result.push(`${typeMap[ruleType]}, ${content}, ${sub.brand}`);
        }

        return result;

    } catch (e) {
        console.log("抓取规则失败:", sub.url, e);
        return [];
    }
}

(async () => {
    const subs = await fetchJson(subscriptionsUrl);
    let allItems = [];

    for (const sub of subs) {
        const rules = await fetchRules(sub);
        allItems = allItems.concat(rules);
    }

    // $done 是圈X调用解析器必须使用的接口
    $done({ items: allItems });
})();
