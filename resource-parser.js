// rule-parser.js
// Quantumult X 规则集解析器（专为规则集格式设计，如 AdBlock/DNSmasq 列表）
// 基于 KOP-XIAO 的资源解析器精简版，专注于规则解析
// 支持 DOMAIN-SET 格式或其他规则集的转换
// 使用方法：在 Quantumult X 配置中设置 resource_parser_url = https://your-url/rule-parser.js
// 示例订阅链接：https://whatshub.top/rule/Google.list#type=domain-set&policy=Shawn

// Base64 编码/解码工具（用于输出编码，如果需要）
function Base64Code() {
  const b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const b64tab = (function(bin) {
    const t = {};
    for (let i = 0, l = bin.length; i < l; i++) t[bin.charAt(i)] = i;
    return t;
  })(b64chars);
  const fromCharCode = String.fromCharCode;

  const cb_utob = function(c) {
    if (c.length < 2) {
      const cc = c.charCodeAt(0);
      return cc < 0x80 ? c
        : cc < 0x800 ? (fromCharCode(0xc0 | (cc >>> 6)) + fromCharCode(0x80 | (cc & 0x3f)))
        : (fromCharCode(0xe0 | ((cc >>> 12) & 0x0f)) + fromCharCode(0x80 | ((cc >>> 6) & 0x3f)) + fromCharCode(0x80 | (cc & 0x3f)));
    } else {
      const cc = 0x10000 + (c.charCodeAt(0) - 0xD800) * 0x400 + (c.charCodeAt(1) - 0xDC00);
      return (fromCharCode(0xf0 | ((cc >>> 18) & 0x07)) + fromCharCode(0x80 | ((cc >>> 12) & 0x3f)) + fromCharCode(0x80 | ((cc >>> 6) & 0x3f)) + fromCharCode(0x80 | (cc & 0x3f)));
    }
  };
  const re_utob = /[\uD800-\uDBFF][\uDC00-\uDFFFF]|[^\x00-\x7F]/g;
  const utob = function(u) { return u.replace(re_utob, cb_utob); };
  const cb_encode = function(ccc) {
    const padlen = [0, 2, 1][ccc.length % 3];
    const ord = ccc.charCodeAt(0) << 16 | ((ccc.length > 1 ? ccc.charCodeAt(1) : 0) << 8) | ((ccc.length > 2 ? ccc.charCodeAt(2) : 0));
    const chars = [
      b64chars.charAt(ord >>> 18),
      b64chars.charAt((ord >>> 12) & 63),
      padlen >= 2 ? '=' : b64chars.charAt((ord >>> 6) & 63),
      padlen >= 1 ? '=' : b64chars.charAt(ord & 63)
    ];
    return chars.join('');
  };
  const btoa = function(b) { return b.replace(/[\s\S]{1,3}/g, cb_encode); };

  this.encode = function(u) {
    return btoa(utob(String(u)));
  };
}

const Base64 = new Base64Code();

// 参数解析
function parseParameters(link) {
  const para = /^(http|https)\:\/\//.test(link) ? link : link.split("\n")[0];
  const para1 = para.includes("#") ? para.split("#")[1] : "";
  const mark0 = para.includes("#");
  return {
    type: mark0 && para1.includes("type=") ? para1.split("type=")[1].split("&")[0] : "domain-set",
    policy: mark0 && para1.includes("policy=") ? decodeURIComponent(para1.split("policy=")[1].split("&")[0]) : "Shawn",
    in: mark0 && para1.includes("in=") ? para1.split("in=")[1].split("&")[0].split("+").map(decodeURIComponent) : null,
    out: mark0 && para1.includes("out=") ? para1.split("out=")[1].split("&")[0].split("+").map(decodeURIComponent) : null,
    regex: mark0 && para1.includes("regex=") ? decodeURIComponent(para1.split("regex=")[1].split("&")[0]) : null,
    regout: mark0 && para1.includes("regout=") ? decodeURIComponent(para1.split("regout=")[1].split("&")[0]) : null,
    hide: mark0 && para1.includes("hide=") ? para1.split("hide=")[1].split("&")[0] : 0,
    ntf: mark0 && para1.includes("ntf=") ? para1.split("ntf=")[1].split("&")[0] : 1
  };
}

// 类型检查（针对规则集）
function Type_Check(subs) {
  const subi = subs.toLowerCase().replace(/ /g, "");
  const lines = subs.split("\n").filter(Boolean);
  
  // 检查是否为域名列表（domain-set 或 HOST）
  if (lines.length > 0 && lines.every(line => /^[\w\.-]+\.(com|org|net|io|top|google|etc)$/i.test(line.trim()) || line.startsWith("||") || line.startsWith("http"))) {
    return "domain-set";
  }
  
  // AdBlock 格式检查（||domain^ 等）
  if (subi.includes("||") || subi.includes("^") || subi.includes("@@")) {
    return "adblock";
  }
  
  // Surge RULE-SET 格式
  if (subi.includes("payload:") || subi.includes("rule-set:")) {
    return "surge-rule-set";
  }
  
  // 其他规则格式
  const RuleK = ["host,", "-suffix,", "domain,", "-keyword,", "ip-cidr,"];
  if (RuleK.some(k => subi.includes(k))) {
    return "Rule";
  }
  
  return "unknown";
}

// 规则过滤
function FilterRules(rules, pin, pout) {
  if (!pin && !pout) return rules;
  return rules.filter(rule => {
    let keep = true;
    if (pin) keep = pin.some(keyword => rule.includes(keyword));
    if (pout) keep = keep && !pout.some(keyword => rule.includes(keyword));
    return keep;
  });
}

// 正则保留/删除
function RegexFilter(rule) {
  if (regex) {
    try {
      if (!rule.match(new RegExp(regex, "i"))) return null;
    } catch (e) {
      console.error("Regex error:", e);
    }
  }
  return rule;
}

function RegexOutFilter(rule) {
  if (regout) {
    try {
      if (rule.match(new RegExp(regout, "i"))) return null;
    } catch (e) {
      console.error("RegexOut error:", e);
    }
  }
  return rule;
}

// AdBlock 到 Quantumult X 规则转换
function AdBlockToQX(content) {
  const lines = content.split("\n").filter(Boolean).map(line => line.trim());
  let qxRules = [];
  for (let line of lines) {
    // 跳过注释
    if (line.startsWith("!") || line.startsWith("[") || line === "") continue;
    
    // 处理 AdBlock 规则
    if (line.startsWith("||")) {
      // ||example.com^ -> DOMAIN-SUFFIX,example.com
      let domain = line.replace("||", "").replace("^", "").replace("*.", "");
      if (domain.endsWith("^")) domain = domain.slice(0, -1);
      qxRules.push(`DOMAIN-SUFFIX,${domain},Shawn`);
    } else if (line.startsWith("http")) {
      // URL 规则 -> URL-REGEX
      qxRules.push(`URL-REGEX,${line},Shawn`);
    } else if (line.includes(".")) {
      // 简单域名 -> DOMAIN
      qxRules.push(`DOMAIN,${line},Shawn`);
    }
    // 可以扩展更多 AdBlock 规则处理
  }
  return qxRules.join("\n");
}

// 域名列表到 DOMAIN-SET 转换
function DomainListToSet(content, policy) {
  const domains = content.split("\n")
    .filter(line => line.trim() && !line.startsWith("#") && !line.startsWith("!"))
    .map(line => line.trim().replace(/^(\|\||https?:\/\/)/, "").replace(/\^.*$/, ""))
    .filter(domain => domain.includes(".") && !domain.startsWith("http"));
  
  // 生成 DOMAIN-SET 格式
  let setContent = `[${policy}]\n`;
  setContent += domains.map(domain => `host-suffix,${domain}`).join("\n");
  
  // Base64 编码 DOMAIN-SET（Quantumult X 标准）
  return `data:application/vnd.quantumultx.domain-set;base64,${Base64.encode(setContent)}`;
}

// Surge RULE-SET 到 QX 转换（简化）
function SurgeRuleSetToQX(content, policy) {
  // 假设 content 是 Surge RULE-SET 的 YAML 内容
  try {
    const yamlData = YAML.parse(content);
    // 处理 payload 中的规则
    if (yamlData.payload) {
      return yamlData.payload.map(rule => {
        // 示例转换：Surge domain -> QX DOMAIN
        if (rule.startsWith("DOMAIN-SUFFIX")) {
          const parts = rule.split(",");
          return `DOMAIN-SUFFIX,${parts[1]},${policy}`;
        }
        return rule; // 其他规则直接使用
      }).join("\n");
    }
  } catch (e) {
    $notify("⚠️", "Surge RULE-SET 解析失败", String(e));
  }
  return content; // 回退到原始内容
}

// 主解析函数（针对规则集）
function RuleParse() {
  const link0 = $resource.link || "";
  let content0 = $resource.content || "";
  const subtag = $resource.tag || "Rule Set";
  const typeU = $resource.type || "";

  // 参数解析
  const params = parseParameters(link0);
  let { type, policy, in: Pin0, out: Pout0, regex, regout, hide, ntf } = params;
  if (typeU) type = typeU; // 强制类型

  // 通知开关
  const showNotify = ntf != 0;

  const detectedType = Type_Check(content0);
  if (showNotify && detectedType !== type) {
    $notify("⚠️ 类型不匹配", `检测到 ${detectedType}，但指定 ${type}`, "继续使用指定类型");
  }

  let total = "";
  let ruleCount = 0;

  // 根据类型转换
  if (type === "domain-set" || detectedType === "domain-set") {
    total = DomainListToSet(content0, policy);
    ruleCount = content0.split("\n").filter(Boolean).length;
  } else if (type === "adblock" || detectedType === "adblock") {
    let rules = AdBlockToQX(content0).split("\n").filter(Boolean);
    if (Pin0 || Pout0) rules = FilterRules(rules, Pin0, Pout0);
    if (regex) rules = rules.map(RegexFilter).filter(Boolean);
    if (regout) rules = rules.map(RegexOutFilter).filter(Boolean);
    total = rules.join("\n");
    ruleCount = rules.length;
  } else if (type === "surge-rule-set" || detectedType === "surge-rule-set") {
    total = SurgeRuleSetToQX(content0, policy);
    ruleCount = total.split("\n").filter(Boolean).length;
  } else if (type === "Rule") {
    let rules = content0.split("\n").map(item => item.trim()).filter(Boolean);
    if (Pin0 || Pout0) rules = FilterRules(rules, Pin0, Pout0);
    if (regex) rules = rules.map(RegexFilter).filter(Boolean);
    if (regout) rules = rules.map(RegexOutFilter).filter(Boolean);
    total = rules.join("\n");
    ruleCount = rules.length;
  } else {
    $notify("❌ 未知规则格式", `不支持 ${detectedType} 或 ${type}`, "请检查链接或指定 type=domain-set 等", { "open-url": link0 });
    return "";
  }

  // 隐藏模式：不删除，而是注释规则（如果 hide=0）
  if (hide === 0 && (Pout0 || regout)) {
    // 逻辑：对于被 out/regout 过滤的规则，使用 [reject] 或注释
    // 这里简化：假设总规则中过滤掉的用 # 注释
    // 实际实现需跟踪过滤的规则
    total = total.replace(/^(.*)$/gm, (match, p1) => {
      // 示例：如果规则包含 out 关键词，注释它
      if (Pout0 && Pout0.some(kw => p1.includes(kw))) return `# ${p1}`;
      return p1;
    });
  }

  if (showNotify) {
    $notify("✅ 规则解析成功", `${subtag}: ${ruleCount} 条规则`, `类型: ${type}, 策略: ${policy}`, { "open-url": link0 });
  }

  return total;
}

// 主入口
try {
  const total = RuleParse();
  $done({ content: total });
} catch (err) {
  $notify("❌ 规则解析失败", "发生错误", String(err), { "open-url": "https://t.me/Shawn_Parser_Bot" });
  $done({ content: "" });
}
