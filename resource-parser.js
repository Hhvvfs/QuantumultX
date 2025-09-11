/**
 * parser-quanx-nodes-rules.js
 * 功能：节点解析（vmess/ss/ssr/trojan）与规则解析（小火箭/Surge/Clash -> Quantumult X）
 * 支持参数（通过 URL#param=val&... 传入）:
 *   in       : 名称包含关键词才保留（关键词用 + 连接）
 *   out      : 名称包含关键词就剔除（关键词用 + 连接）
 *   regex    : 用正则匹配整行（full text），只保留匹配的
 *   rename   : 重命名规则，格式支持 多项用 + 链接，each: old@new ; 支持 @后缀 / 前缀@
 *   policy   : 规则第三字段统一替换为该策略名（例如 "国际网络"）
 *   sort     : 1(按名前升序) / -1(降序) / x(随机)
 *
 * 返回：处理后的文本（供 Quantumult X 使用）
 */

(function () {
  // ------ helpers ------
  function parseParams(paramString) {
    const params = {};
    if (!paramString) return params;
    paramString.split('&').forEach(kv => {
      const [k, ...rest] = kv.split('=');
      if (!k) return;
      const v = rest.join('=');
      params[k] = decodeURIComponent(v || '');
    });
    return params;
  }

  function ensureBase64Padding(s) {
    if (!s) return s;
    return s + '='.repeat((4 - (s.length % 4)) % 4);
  }

  function b64dec(s) {
    try {
      // try atob (JSCore in many mobile apps)
      return decodeURIComponent(Array.prototype.map.call(atob(ensureBase64Padding(s)), c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
    } catch (e) {
      try {
        return atob(ensureBase64Padding(s));
      } catch (e2) {
        return null;
      }
    }
  }

  function b64enc(s) {
    try {
      return btoa(unescape(encodeURIComponent(s)));
    } catch (e) {
      try {
        return btoa(s);
      } catch (e2) {
        return null;
      }
    }
  }

  function isLikelyBase64All(str) {
    if (!str) return false;
    // allow newlines trimmed
    const t = str.trim();
    // check it's longer than a few chars and only base64 chars (+/=)
    return /^[A-Za-z0-9+/=\s]+$/.test(t) && t.length > 32;
  }

  function matchesKeyword(name = '', keywords) {
    if (!keywords) return false;
    return keywords.split('+').some(kw => name.includes(kw));
  }

  function applyRename(name, renameParam) {
    if (!renameParam || !name) return name;
    let out = name;
    renameParam.split('+').forEach(pair => {
      if (!pair) return;
      const [oldStr, newStr] = pair.split('@');
      if (oldStr && newStr !== undefined) {
        // replace all occurrences (literal)
        out = out.split(oldStr).join(newStr);
      } else if (oldStr && newStr === undefined) {
        if (pair.startsWith('@')) {
          out = out + pair.substring(1);
        } else if (pair.endsWith('@')) {
          out = pair.substring(0, pair.length - 1) + out;
        }
      }
    });
    return out;
  }

  function sortItems(items, sortParam) {
    if (!sortParam) return items;
    if (sortParam === '1') {
      return items.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    } else if (sortParam === '-1') {
      return items.sort((a, b) => (b.name || '').localeCompare(a.name || ''));
    } else if (sortParam.toLowerCase() === 'x') {
      return items.sort(() => Math.random() - 0.5);
    }
    return items;
  }

  // ------ node parsers ------
  function extractNameFromVMessJson(j) {
    if (!j) return null;
    if (j.ps) return j.ps;
    if (j.ps || j.p) return j.ps || j.p;
    return null;
  }

  function normalizeVMess(link) {
    // vmess://BASE64_JSON  或 vmess://{"v":...} 这种少见形式
    const payload = link.replace(/^vmess:\/\//i, '').trim();
    let jsonStr = null;
    // try base64 decode
    const dec = b64dec(payload);
    if (dec && dec.indexOf('"') !== -1) {
      jsonStr = dec;
    } else if (payload.startsWith('{')) {
      jsonStr = payload;
    }
    if (!jsonStr) return null;
    try {
      const j = JSON.parse(jsonStr);
      // ensure ps exists
      if (!j.ps) j.ps = j.ps || (j.p && j.p) || `${j.add || j.host || 'vmess'}:${j.port || ''}`;
      const rebuilt = b64enc(JSON.stringify(j));
      return `vmess://${rebuilt}`;
    } catch (e) {
      return null;
    }
  }

  function parseSSR(link) {
    // ssr://BASE64  -> decode 部分得到  server:port:protocol:method:obfs:base64passwd/?params
    const payload = link.replace(/^ssr:\/\//i, '').trim();
    const dec = b64dec(payload);
    if (!dec) return null;
    // try extract remarks param
    const parts = dec.split('/?');
    const meta = parts[1] || '';
    const params = {};
    meta.split('&').forEach(kv => {
      if (!kv) return;
      const [k, v] = kv.split('=');
      params[k] = v;
    });
    let remark = null;
    if (params.remarks) {
      remark = b64dec(params.remarks);
    }
    // we will return original ssr://BASE64 to keep exact info (Quantumult X supports ssr links)
    return `ssr://${b64enc(dec)}`; // canonicalize padding
  }

  function normalizeSS(link, maybeTagFromHash) {
    // support forms:
    // ss://BASE64  (BASE64 -> method:password@host:port)
    // ss://method:password@host:port
    // optionally with #tag at end
    let url = link.trim();
    // remove possible surrounding <>
    url = url.replace(/^<|>$/g, '');
    // separate fragment
    const fragMatch = url.match(/#(.+)$/);
    const frag = fragMatch ? decodeURIComponent(fragMatch[1]) : maybeTagFromHash || '';
    let core = url.replace(/#.*$/, '').replace(/^ss:\/\//i, '');
    // if core contains '@' likely form method:password@host:port
    if (core.indexOf('@') !== -1 && core.indexOf(':') !== -1) {
      // we will encode method:password@host:port as base64 then return ss://BASE64#tag (canonical)
      const b = b64enc(core);
      if (!b) return null;
      if (frag) return `ss://${b}#${encodeURIComponent(frag)}`;
      return `ss://${b}`;
    } else {
      // assume base64 payload
      const dec = b64dec(core);
      if (!dec) return null;
      // dec might be like method:password@host:port or method:password
      // if dec is "method:password" without host:port, some subscriptions separate host after "#"? we keep as-is
      const b = b64enc(dec);
      if (!b) return null;
      if (frag) return `ss://${b}#${encodeURIComponent(frag)}`;
      return `ss://${b}`;
    }
  }

  function normalizeTrojan(link) {
    // trojan://password@host:port?params#tag
    // just ensure fragment is present; return normalized trojan://... (leave params)
    return link.replace(/\s+/g, '');
  }

  // ------ overall node processing ------
  function collectNodeLinks(text) {
    let t = text || '';
    t = t.trim();
    // if whole payload is base64 (common in some subs), decode once
    if (isLikelyBase64All(t) && !(t.includes('vmess://') || t.includes('ss://') || t.includes('ssr://') || t.includes('trojan://'))) {
      const dec = b64dec(t);
      if (dec) t = dec;
    }
    // find url-like links and also lines that look like plain nodes
    const regex = /(vmess:\/\/[A-Za-z0-9+=\/]+|vmess:\{[\s\S]*?\}|ssr:\/\/[A-Za-z0-9+=\/]+|ss:\/\/[^\s'"]+|trojan:\/\/[^\s'"]+)/ig;
    const matches = [];
    let m;
    while ((m = regex.exec(t)) !== null) {
      matches.push(m[0]);
    }
    // also capture lines fully non-url but look like host:port entries (surge server lines rarely appear here) — ignore for now
    return Array.from(new Set(matches)); // unique
  }

  function buildNodeItem(rawLink) {
    // returns { full, name, proto }
    const l = rawLink.trim();
    if (/^vmess:\/\//i.test(l)) {
      const norm = normalizeVMess(l);
      if (!norm) return { full: l, name: l, proto: 'vmess' };
      // try get name
      const payload = norm.replace(/^vmess:\/\//i, '');
      const dec = b64dec(payload);
      let name = null;
      try {
        const j = JSON.parse(dec);
        name = extractNameFromVMessJson(j) || j.add || `${j.add || 'vmess'}:${j.port || ''}`;
      } catch (e) {
        name = 'vmess';
      }
      return { full: norm, name, proto: 'vmess' };
    } else if (/^ssr:\/\//i.test(l)) {
      const norm = parseSSR(l) || l;
      // try extract name
      const payload = norm.replace(/^ssr:\/\//i, '');
      const dec = b64dec(payload);
      let name = 'ssr';
      if (dec) {
        const parts = dec.split('/?');
        const meta = (parts[1] || '');
        const params = {};
        meta.split('&').forEach(kv => {
          if (!kv) return;
          const [k, v] = kv.split('=');
          params[k] = v;
        });
        if (params.remarks) {
          const r = b64dec(params.remarks);
          if (r) name = r;
        }
      }
      return { full: norm, name, proto: 'ssr' };
    } else if (/^ss:\/\//i.test(l)) {
      // fragment might be included in raw link
      const norm = normalizeSS(l);
      const frag = (l.match(/#(.+)$/) || [])[1];
      const name = frag ? decodeURIComponent(frag) : 'ss';
      return { full: norm || l, name, proto: 'ss' };
    } else if (/^trojan:\/\//i.test(l)) {
      const norm = normalizeTrojan(l);
      let name = 'trojan';
      const frag = (l.match(/#(.+)$/) || [])[1];
      if (frag) name = decodeURIComponent(frag);
      return { full: norm, name, proto: 'trojan' };
    } else {
      // unknown: return as-is
      return { full: l, name: l, proto: 'unknown' };
    }
  }

  function processNodes(resourceText, params) {
    const rawLinks = collectNodeLinks(resourceText);
    let items = rawLinks.map(buildNodeItem);
    // filter
    items = items.filter(item => {
      if (params.in && !matchesKeyword(item.name || '', params.in)) return false;
      if (params.out && matchesKeyword(item.name || '', params.out)) return false;
      if (params.regex) {
        try {
          const re = new RegExp(params.regex);
          if (!re.test(item.full)) return false;
        } catch (e) {
          // invalid regex -> skip
        }
      }
      return true;
    });
    // rename
    items = items.map(item => {
      item.name = applyRename(item.name, params.rename);
      // try to attach name to fragment for ss/vmess/trojan if not already present
      if (/^ss:\/\//i.test(item.full)) {
        if (!/#/.test(item.full) && item.name) {
          item.full = item.full + '#' + encodeURIComponent(item.name);
        }
      } else if (/^vmess:\/\//i.test(item.full)) {
        // vmess already encodes name in JSON; we could try to decode/replace ps
        try {
          const payload = item.full.replace(/^vmess:\/\//i, '');
          const dec = b64dec(payload);
          const j = JSON.parse(dec);
          j.ps = item.name;
          item.full = 'vmess://' + b64enc(JSON.stringify(j));
        } catch (e) {
          // ignore
        }
      } else if (/^trojan:\/\//i.test(item.full)) {
        if (!/#/.test(item.full) && item.name) {
          item.full = item.full + '#' + encodeURIComponent(item.name);
        }
      } else if (/^ssr:\/\//i.test(item.full)) {
        // SSR remarks in params: we could rewrite remarks but keep original for safety
      }
      return item;
    });
    items = sortItems(items, params.sort);
    // final output: one node per line (Quantumult X accepts vmess:// / ss:// / ssr:// / trojan://)
    const out = items.map(i => i.full).join('\n');
    return out;
  }

  // ------ rule parsing ------
  function normalizeRuleLine(line, params) {
    // trim and skip comments
    let l = line.trim();
    if (!l) return null;
    if (l.startsWith('#') || l.startsWith('!')) return null;

    // some rules appear quoted in YAML: ' - "DOMAIN-SUFFIX,google.com,Proxy" ' -> remove quotes
    l = l.replace(/^['"]+|['"]+$/g, '');

    // Host file entry: "127.0.0.1 example.com" -> convert to DOMAIN-SUFFIX,example.com,<policy>
    const hostEntry = l.match(/^\s*\d{1,3}(?:\.\d{1,3}){3}\s+([^\s#]+)/);
    if (hostEntry) {
      const domain = hostEntry[1];
      const policy = params.policy || 'REJECT';
      return `DOMAIN-SUFFIX,${domain},${policy}`;
    }

    // Surge/Shadowrocket style lines: TYPE,pattern,policy[,option...]
    // Some lines may use lowercase types; normalize to uppercase.
    // If line is 'FINAL,REJECT' or 'FINAL,DIRECT'
    const parts = l.split(',');
    if (parts.length >= 2) {
      const type = parts[0].trim().toUpperCase();
      const pattern = parts[1].trim();
      let policy = parts[2] ? parts[2].trim() : (params.policy || 'DIRECT');
      // override if params.policy provided
      if (params.policy) policy = params.policy;
      // map some common type names to Quantumult X style
      const mapType = {
        'DOMAIN': 'DOMAIN-SUFFIX', // domain -> suffix (best effort)
        'DOMAIN-SUFFIX': 'DOMAIN-SUFFIX',
        'DOMAIN-KEYWORD': 'DOMAIN-KEYWORD',
        'IP-CIDR': 'IP-CIDR',
        'IP-CIDR6': 'IP-CIDR6',
        'GEOIP': 'GEOIP',
        'FINAL': 'FINAL',
        'PROCESS-NAME': 'PROCESS-NAME',
        'USER-AGENT': 'USER-AGENT',
        'URL-REGEX': 'URL-REGEX',
        'HOST': 'DOMAIN-SUFFIX'
      };
      const nt = mapType[type] || type;
      // rebuild, preserve extra options after third field (like tag=... or remark)
      const extra = parts.slice(3).map(x => x.trim()).filter(x => x).join(',');
      const rebuilt = extra ? `${nt},${pattern},${policy},${extra}` : `${nt},${pattern},${policy}`;
      return rebuilt;
    }

    // Clash YAML sometimes has single-value rules lines like ' - DOMAIN-SUFFIX,google.com,Proxy'
    // If not matched above, return as-is
    return l;
  }

  function processRules(resourceText, params) {
    const lines = resourceText.split('\n');
    const outLines = [];
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];
      const n = normalizeRuleLine(raw, params);
      if (!n) continue;
      // filter by regex/in/out on the string or name part
      // try to extract name/key from rule: use pattern portion (2nd field)
      const pattern = (n.split(',')[1] || '');
      if (params.in && !matchesKeyword(pattern, params.in)) continue;
      if (params.out && matchesKeyword(pattern, params.out)) continue;
      if (params.regex) {
        try {
          const re = new RegExp(params.regex);
          if (!re.test(n)) continue;
        } catch (e) { /* invalid regex -> ignore */ }
      }
      outLines.push(n);
    }
    const sorted = sortItems(outLines.map(l => ({ name: l, full: l })), params.sort).map(x => x.full);
    return sorted.join('\n');
  }

  // ------ main entry ------
  function isNodeText(txt) {
    if (!txt) return false;
    const lower = txt.toLowerCase();
    return /vmess:\/\//.test(lower) || /ss:\/\//.test(lower) || /ssr:\/\//.test(lower) || /trojan:\/\//.test(lower);
  }

  function isRuleText(txt) {
    if (!txt) return false;
    // rule files often contain commas and keywords like DOMAIN-SUFFIX or IP-CIDR or final lines
    const up = txt.toUpperCase();
    return up.includes('DOMAIN-SUFFIX') || up.includes('IP-CIDR') || up.includes('FINAL') || up.includes('GEOIP') || txt.split('\n').some(l => /,/.test(l));
  }

  function main(url, resourceText) {
    const [baseUrl, paramString] = (url || '').split('#');
    const params = parseParams(paramString || '');
    // detect content type: node list or rule list
    if (isNodeText(resourceText)) {
      return processNodes(resourceText, params);
    } else if (isRuleText(resourceText)) {
      return processRules(resourceText, params);
    } else {
      // fallback: try both heuristics
      const nodes = processNodes(resourceText, params);
      if (nodes && nodes.trim()) return nodes;
      return processRules(resourceText, params);
    }
  }

  // expose
  return { parse: main };
})();
