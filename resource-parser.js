// rule-parser.js
// Quantumult X 规则集解析器（专为规则集格式设计，如 AdBlock/DOMAIN-SET）
// 针对 https://whatshub.top/rule/Google.list 优化
// 使用方法：在 [general] 中设置 resource_parser_url = https://your-url/rule-parser.js
// 示例订阅链接：https://whatshub.top/rule/Google.list#type=domain-set&policy=Proxy&in=google

// Base64 编码/解码工具
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
  
  // 检查是否为域名列表（DOMAIN-SET）
  if (lines.length > 0 && lines.every(line => /^[\w\.-]+\.(com|org|net|io|top|google|etc)$/i.test(line.trim()) || line.startsWith("||"))) {
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
function RegexFilter(rule, regex) {
  if (regex) {
    try {
      if (!rule.match(new RegExp(regex, "i"))) return null;
    } catch (e) {
      console.error("Regex error:", e);
      return rule; // 容错
    }
  }
  return rule;
}

function RegexOutFilter(rule, regout) {
  if (regout) {
    try {
      if (rule.match(new RegExp(regout, "i"))) return null;
    } catch (e) {
      console.error("RegexOut error:", e);
      return rule; // 容错
    }
  }
  return rule;
}

// AdBlock 到 Quantumult X 规则转换
function AdBlockToQX(content, policy) {
  const lines = content.split("\n").filter(line => line.trim() && !line.startsWith("!") && !line.startsWith("[") && !line.startsWith("#"));
  let qxRules = [];
  for (let line of lines) {
    if (line.startsWith("||")) {
      let domain = line.replace("||", "").replace("^", "").replace("*.", "");
      if (domain.endsWith("^")) domain = domain.slice(0, -1);
      qxRules.push(`DOMAIN-SUFFIX,${domain},${policy}`);
    } else if (line.includes(".")) {
      qxRules.push(`DOMAIN,${line},${policy}`);
    }
    // 扩展其他 AdBlock 规则（如 @@ 为白名单）
    else if (line.startsWith("@@||")) {
      domain = line.replace("@@||", "").replace("^", "").replace("*.", "");
      if (domain.endsWith("^")) domain = domain.slice(0, -1);
      qxRules.push(`DOMAIN-SUFFIX,${domain},DIRECT`);
    }
  }
  return qxRules.filter(Boolean).join("\n");
}

// 域名列表到 DOMAIN-SET 转换
function DomainListToSet(content, policy) {
  const domains = content.split("\n")
    .filter(line => line.trim() && !line.startsWith("#") && !line.startsWith("!"))
    .map(line => line.trim().replace(/^(\|\||https?:\/\/)/, "").replace(/\^.*$/, ""))
    .filter(domain => domain.includes(".") && !domain.startsWith("http"));
  
  if (domains.length === 0) return "";
  
  let setContent = `[${policy}]\n`;
  setContent += domains.map(domain => `host-suffix,${domain}`).join("\n");
  return `data:application/vnd.quantumultx.domain-set;base64,${Base64.encode(setContent)}`;
}

// 主解析函数（针对规则集）
function RuleParse() {
  const link0 = $resource.link || "";
  let content0 = $resource.content || "";
  const subtag = $resource.tag || "Rule Set";

  // 检查内容是否有效
  if (!content0 || content0.trim() === "") {
    $notify("❌ 内容为空", `${subtag} 没有获取到有效内容`, "请检查链接", { "open-url": link0 });
    return $done({ content: "" });
  }

  // 参数解析
  const params = parseParameters(link0);
  let { type, policy, in: Pin0, out: Pout0, regex, regout, hide, ntf } = params;
  const showNotify = ntf != 0;

  const detectedType = Type_Check(content0);
  if (showNotify && detectedType !== type && type !== "unknown") {
    $notify("⚠️ 类型不匹配", `检测到 ${detectedType}，但指定 ${type}`, "继续使用指定类型");
  }
  if (type === "unknown") type = detectedType;

  let total = "";
  let ruleCount = 0;

  // 根据类型转换
  if (type === "domain-set" || detectedType === "domain-set") {
    total = DomainListToSet(content0, policy);
    ruleCount = content0.split("\n").filter(Boolean).length;
  } else if (type === "adblock" || detectedType === "adblock") {
    let rules = AdBlockToQX(content0, policy).split("\n").filter(Boolean);
    if (Pin0 || Pout0) rules = FilterRules(rules, Pin0, Pout0);
    if (regex) rules = rules.map(rule => RegexFilter(rule, regex)).filter(Boolean);
    if (regout) rules = rules.map(rule => RegexOutFilter(rule, regout)).filter(Boolean);
    total = rules.join("\n");
    ruleCount = rules.length;
  } else {
    $notify("❌ 未知规则格式", `不支持 ${detectedType} 或 ${type}`, "请指定 type=domain-set 或 adblock", { "open-url": link0 });
    return $done({ content: "" });
  }

  // 隐藏模式：注释而非删除
  if (hide === 0 && (Pout0 || regout)) {
    total = total.split("\n").map(line => {
      if (Pout0 && Pout0.some(kw => line.includes(kw))) return `# ${line}`;
      if (regout && line.match(new RegExp(regout, "i"))) return `# ${line}`;
      return line;
    }).join("\n");
  }

  if (showNotify && total) {
    $notify("✅ 规则解析成功", `${subtag}: ${ruleCount} 条规则`, `类型: ${type}, 策略: ${policy}`, { "open-url": link0 });
  } else if (showNotify && !total) {
    $notify("⚠️ 解析结果为空", `${subtag} 无有效规则`, "请检查链接或参数", { "open-url": link0 });
  }

  return $done({ content: total });
}

// 主入口
try {
  RuleParse();
} catch (err) {
  $notify("❌ 规则解析失败", "发生错误", String(err), { "open-url": "https://t.me/Shawn_Parser_Bot" });
  $done({ content: "" });
}
