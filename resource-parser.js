/**
 * Quantumult X 专用 — 仅节点解析 & 分流规则解析
 * 用法：在订阅链接后使用 # 参数（in/out/regex/rename/sort/policy）
 *
 * 导出接口：返回 { parse: function(url, resourceText) { ... } }
 *
 * 支持解析： vmess://, ss://, ssr://, trojan:// 以及已有的 Quantumult X 节点行
 * 支持规则转换：Surge/Shadowrocket 常见类型 -> Quantumult X 语法
 *
 * 注意：尽量在设备上多测几种订阅样例，某些 provider 的变体很多，必要时我可再迭代增强。
 */

(function() {
  // ----------- utils -----------
  function safeAtob(s) {
    if (typeof atob === 'function') return atob(s);
    // minimal base64 fallback (may not exist in some environments)
    try { return Buffer.from(s, 'base64').toString('binary'); } catch (e) { return null; }
  }
  function b64DecodeUnicode(str) {
    try {
      // 尝试 URL-safe 修正
      str = str.replace(/-/g, '+').replace(/_/g, '/');
      while (str.length % 4) str += '=';
      const bin = safeAtob(str);
      if (bin === null) return null;
      // decode UTF-8
      try {
        return decodeURIComponent(Array.prototype.map.call(bin, function(c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
      } catch (e) {
        return bin;
      }
    } catch (e) {
      return null;
    }
  }
  function tryBase64DecodeIfLooksLike(s) {
    if (!s || s.length < 8) return null;
    // 判定为 base64 字符串（含 url-safe）
    if (/^[A-Za-z0-9\-_+=\/]+$/.test(s.replace(/\s+/g, ''))) {
      return b64DecodeUnicode(s.trim());
    }
    return null;
  }
  function parseParams(paramString) {
    const params = {};
    if (!paramString) return params;
    paramString.split('&').forEach(kv => {
      if (!kv) return;
      const [k, ...rest] = kv.split('=');
      const v = rest.join('=');
      if (!k) return;
      try { params[k] = decodeURIComponent(v || ''); } catch(e) { params[k] = v || ''; }
    });
    return params;
  }
  function splitOnce(s, sep) {
    const i = s.indexOf(sep);
    if (i === -1) return [s];
    return [s.slice(0, i), s.slice(i + sep.length)];
  }
  function safeTrim(s){ return (s||'').trim(); }

  // ----------- node parsers -----------
  function parseVmessLine(line) {
    // vmess://<base64>[#name]
    const withoutPrefix = line.replace(/^vmess:\/\//i, '');
    const [payloadWithParams] = withoutPrefix.split('#');
    const payload = payloadWithParams;
    const dec = tryBase64DecodeIfLooksLike(payload) || payload;
    let json = null;
    try { json = JSON.parse(dec); } catch(e) {
      // 有时 vmess:// 后直接是 JSON 字符串或带 params 的格式，尝试去除 prefix
      try { json = JSON.parse(decodeURIComponent(payload)); } catch(e2) { json = null; }
    }
    if (!json) return null;

    const add = json.add || json.add || json.server || '';
    const port = json.port || json.port || json.port || '';
    const id = json.id || json.uuid || '';
    const ps = json.ps || json.remarks || json.remarks || '';
    const net = (json.net || json.network || '').toLowerCase();
    const tls = json.tls === 'tls' || json.tls === '1' || json.tls === true;
    const host = json.host || json.sni || json.host || '';
    const path = json.path || json.wsPath || json.path || '';
    const alpn = json.alpn || '';

    let lineOut = `vmess=${add}:${port}, method=none, password=${id}, fast-open=false, udp-relay=false, tag=${ps || (add + ':' + port)}`;
    // network / obfs handling (依据 Quantumult X 示例)
    if (net === 'ws') {
      lineOut += ', obfs=' + (tls ? 'wss' : 'ws');
      if (path) lineOut += `, obfs-uri=${path}`;
      if (host) lineOut += `, obfs-host=${host}`;
    } else {
      if (tls) {
        lineOut += ', obfs=over-tls';
        if (host) lineOut += `, obfs-host=${host}`;
      }
      // 对于其它传输（tcp/h2/quic）先不特殊处理，输出基本字段
    }
    if (alpn) lineOut += `, alpn=${alpn}`;
    return { type: 'vmess', name: ps || `${add}:${port}`, qx: lineOut, raw: line };
  }

  function parseSSLine(line) {
    // ss:// base64 或 ss://method:pass@host:port#name 或带 ?plugin=
    let rest = line.replace(/^ss:\/\//i, '');
    let tag = '';
    if (rest.includes('#')) {
      const parts = rest.split('#');
      rest = parts[0];
      tag = decodeURIComponent(parts.slice(1).join('#')) || '';
    }
    // 如果 rest 不含 '@'，可能是 base64
    let info = '';
    if (rest.indexOf('@') === -1) {
      // rest 可能是 base64 或 base64url
      const dec = tryBase64DecodeIfLooksLike(rest) || rest;
      info = dec;
    } else {
      info = rest;
    }
    // info 可能包含 ?plugin=...
    const [beforeQ, afterQ] = splitOnce(info, '?');
    const main = beforeQ;
    const pluginStr = afterQ || '';
    // main 可能是 method:password@host:port or method:password@ipv6:port
    const m = main.match(/^([^:]+):([^@]+)@(.+):(\d+)$/);
    if (!m) return null;
    const method = m[1];
    const password = m[2];
    const host = m[3];
    const port = m[4];
    let obfs = '';
    let obfsHost = '';
    let obfsUri = '';

    if (pluginStr) {
      // plugin=obfs-local;obfs=http;obfs-host=bing.com;obfs-uri=/x
      const kvs = pluginStr.split(';');
      kvs.forEach(kv => {
        const [k, v] = splitOnce(kv, '=');
        const kk = (k||'').toLowerCase();
        if (kk.includes('obfs')) {
          if (v) {
            if (v === 'http' || v === 'tls' || v === 'wss' || v === 'ws') obfs = v === 'tls' ? 'wss' : v;
            else if (v.startsWith('obfs=')) obfs = v.replace('obfs=', '');
          }
        }
        if (kk === 'obfs-host') obfsHost = v || '';
        if (kk === 'obfs-uri') obfsUri = v || '';
      });
    }

    let lineOut = `shadowsocks=${host}:${port}, method=${method}, password=${password}, fast-open=false, udp-relay=false, tag=${tag || `${host}:${port}`}`;
    if (obfs) lineOut += `, obfs=${obfs}`;
    if (obfsHost) lineOut += `, obfs-host=${obfsHost}`;
    if (obfsUri) lineOut += `, obfs-uri=${obfsUri}`;
    return { type: 'ss', name: tag || `${host}:${port}`, qx: lineOut, raw: line };
  }

  function parseSSRLine(line) {
    // ssr://<base64>
    const payload = line.replace(/^ssr:\/\//i, '');
    const dec = tryBase64DecodeIfLooksLike(payload);
    if (!dec) return null;
    // SSR 格式: host:port:protocol:method:obfs:base64(pass)/?param=base64
    const [main, paramsPart] = splitOnce(dec, '/?');
    const parts = main.split(':');
    if (parts.length < 6) return null;
    const host = parts[0], port = parts[1], protocol = parts[2], method = parts[3], obfs = parts[4];
    const passB64 = parts.slice(5).join(':'); // base64 password
    const password = b64DecodeUnicode(passB64) || passB64;
    // parse params
    const params = {};
    if (paramsPart) {
      paramsPart.split('&').forEach(kv => {
        const [k, v] = splitOnce(kv, '=');
        if (k && v) params[k] = b64DecodeUnicode(v) || v;
      });
    }
    const remarks = params.remarks || params.remark || '';
    const group = params.group || '';
    // build qx shadowsocks with ssr extras
    let lineOut = `shadowsocks=${host}:${port}, method=${method}, password=${password}, fast-open=false, udp-relay=false, tag=${remarks || (host + ':' + port)}`;
    // SSR 特有
    if (protocol) lineOut += `, ssr-protocol=${protocol}`;
    if (params.protoparam) lineOut += `, ssr-protocol-param=${params.protoparam}`;
    if (obfs) lineOut += `, obfs=${obfs}`;
    if (params.obfsparam) lineOut += `, obfs-host=${params.obfsparam}`;
    return { type: 'ssr', name: remarks || `${host}:${port}`, qx: lineOut, raw: line };
  }

  function parseTrojanLine(line) {
    // trojan://password@host:port#tag or with ?sni=...
    // remove trojan://
    let rest = line.replace(/^trojan:\/\//i, '');
    let tag = '';
    if (rest.includes('#')) {
      const parts = rest.split('#');
      rest = parts[0];
      tag = decodeURIComponent(parts.slice(1).join('#')) || '';
    }
    // rest could have ?params
    const [main, paramsStr] = splitOnce(rest, '?');
    const m = main.match(/^([^@]+)@(.+):(\d+)$/);
    if (!m) return null;
    const password = m[1], host = m[2], port = m[3];
    const params = {};
    if (paramsStr) {
      paramsStr.split('&').forEach(kv => {
        const [k, v] = splitOnce(kv, '=');
        if (k) params[k] = v || '';
      });
    }
    const sni = params.sni || params.sni || '';
    let lineOut = `trojan=${host}:${port}, password=${password}, over-tls=true, tls-verification=false, fast-open=false, udp-relay=false, tag=${tag || `${host}:${port}`}`;
    if (sni) lineOut += `, tls-host=${sni}`;
    return { type: 'trojan', name: tag || `${host}:${port}`, qx: lineOut, raw: line };
  }

  function parseQXNative(line) {
    // 如果已经是 Quantumult X 格式的 server 行（vmess= / shadowsocks= / trojan=），直接认为是原样通过
    const m = line.match(/^(vmess=|shadowsocks=|shadowsocks-v2=|trojan=)/i);
    if (m) {
      // try to extract tag=... if exists
      const tagMatch = line.match(/tag=([^,]+)/i);
      const name = tagMatch ? safeTrim(tagMatch[1]) : (line.slice(0, 40).trim());
      return { type: 'native', name: name, qx: line.trim(), raw: line };
    }
    return null;
  }

  function parseNodeLine(line) {
    line = safeTrim(line);
    if (!line) return null;
    // try native first
    const native = parseQXNative(line);
    if (native) return native;
    if (/^vmess:\/\//i.test(line)) return parseVmessLine(line);
    if (/^ssr:\/\//i.test(line)) return parseSSRLine(line);
    if (/^ss:\/\//i.test(line)) return parseSSLine(line);
    if (/^trojan:\/\//i.test(line)) return parseTrojanLine(line);
    // maybe it's a plain "scheme://addr" or plain "host:port,..."? if line contains '://' but not recognized, skip
    return null;
  }

  // ----------- rules parser -----------
  function convertRuleLine(line) {
    // Trim and ignore comments
    const t = safeTrim(line);
    if (!t || /^;|^#|^\/\//.test(t)) return null;

    // Surge/Shadowrocket style: TYPE,pattern,action[,extra...]
    // Quantumult X style expected: host|host-suffix|host-keyword|ip-cidr|ip6-cidr|geoip|final|user-agent|url-regex
    // mapping:
    const typeMap = {
      'DOMAIN-SUFFIX': 'host-suffix',
      'DOMAIN-KEYWORD': 'host-keyword',
      'DOMAIN': 'host',
      'IP-CIDR': 'ip-cidr',
      'IP-CIDR6': 'ip6-cidr',
      'GEOIP': 'geoip',
      'FINAL': 'final',
      'USER-AGENT': 'user-agent',
      'URL-REGEX': 'url-regex',
      'REGEX': 'url-regex',
      'PROCESS-NAME': 'process-name' // may not be supported; passthrough
    };

    const parts = t.split(',');
    if (parts.length < 2) {
      // maybe already quantumult style like "host, domain, proxy"
      return t;
    }
    const t0 = parts[0].toUpperCase();
    let rest = parts.slice(1).map(s => safeTrim(s));
    if (typeMap[t0]) {
      const newType = typeMap[t0];
      // ensure action exist: last field is action
      const action = rest[rest.length - 1];
      const pat = rest.slice(0, rest.length - 1).join(',');
      let out = `${newType}, ${pat}, ${action}`;
      return out;
    } else {
      // already qx style or unknown -> try to normalize some lowercase keys
      return t;
    }
  }

  // ----------- item filters / rename / sort -----------
  function matchesKeywordAny(name, keywords) {
    if (!keywords) return false;
    return keywords.split('+').some(kw => kw && name.indexOf(kw) !== -1);
  }

  function filterItemsByParams(items, params) {
    return items.filter(item => {
      if (!item) return false;
      // in: 必须包含任意关键词
      if (params.in && !matchesKeywordAny(item.name || item.qx || item.raw || '', params.in)) return false;
      // out: 含有任意关键词则排除
      if (params.out && matchesKeywordAny(item.name || item.qx || item.raw || '', params.out)) return false;
      // regex: 保留匹配 regex 的
      if (params.regex) {
        try {
          const re = new RegExp(params.regex);
          if (!re.test(item.qx || item.raw || item.name || '')) return false;
        } catch (e) { /* ignore invalid regex */ }
      }
      if (params.regout) {
        try {
          const re = new RegExp(params.regout);
          if (re.test(item.qx || item.raw || item.name || '')) return false;
        } catch(e) {}
      }
      return true;
    });
  }

  function applyRename(items, params) {
    if (!params.rename) return items;
    // 支持多条 rename，以 + 分隔，格式 old@new；也支持 @suffix 或 prefix@
    const ops = params.rename.split('+').map(s => s.trim()).filter(Boolean);
    return items.map(item => {
      let name = item.name || '';
      ops.forEach(op => {
        const [oldStr, newStr] = splitOnce(op, '@');
        if (newStr !== undefined && oldStr) {
          // old@new
          try { name = name.replace(new RegExp(oldStr, 'g'), newStr); } catch(e) { name = name.split(oldStr).join(newStr); }
        } else if (op.startsWith('@')) {
          name = name + op.slice(1);
        } else if (op.endsWith('@')) {
          name = op.slice(0, -1) + name;
        }
      });
      item.name = name;
      // also try to replace tag= in qx if present
      if (item.qx && item.qx.indexOf('tag=') !== -1) {
        item.qx = item.qx.replace(/tag=[^,]+/, 'tag=' + name);
      }
      return item;
    });
  }

  function applySort(items, params) {
    if (!params.sort) return items;
    if (params.sort === '1') return items.sort((a,b) => (a.name||'').localeCompare(b.name||''));
    if (params.sort === '-1') return items.sort((a,b) => (b.name||'').localeCompare(a.name||''));
    if (params.sort.toLowerCase() === 'x') return items.sort(() => Math.random()-0.5);
    return items;
  }

  // ----------- main processors -----------
  function processNodes(resourceText, params) {
    // resourceText 可能是整包 base64（多数订阅），尝试 decode
    let text = resourceText;
    const tryDec = tryBase64DecodeIfLooksLike(resourceText.replace(/\s+/g, ''));
    if (tryDec && (tryDec.indexOf('vmess://') !== -1 || tryDec.indexOf('ss://') !== -1 || tryDec.indexOf('ssr://') !== -1 || tryDec.indexOf('trojan://') !== -1)) {
      text = tryDec;
    }
    // split lines by newline and also comma-separated lists sometimes
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l);
    const items = [];
    lines.forEach(line => {
      // some providers pack many uri in one long line separated by comma/space, avoid splitting wrong — keep per-line handling
      // attempt parse
      const parsed = parseNodeLine(line);
      if (parsed) items.push(parsed);
      else {
        // if not parsed, maybe the line contains multiple "vmess://" entries glued; try to extract them
        const found = [];
        const vmessMatches = line.match(/vmess:\/\/[A-Za-z0-9\-_+=\/]+/g);
        if (vmessMatches) vmessMatches.forEach(m => { const p = parseVmessLine(m); if (p) found.push(p); });
        const ssMatches = line.match(/ssr?:\/\/[A-Za-z0-9\-_+=\/@:%?\.]+/g);
        if (ssMatches) ssMatches.forEach(m => { const p = m.startsWith('ssr://') ? parseSSRLine(m) : parseSSLine(m); if (p) found.push(p); });
        const trMatches = line.match(/trojan:\/\/[^,\s]+/g);
        if (trMatches) trMatches.forEach(m => { const p = parseTrojanLine(m); if (p) found.push(p); });
        if (found.length) found.forEach(f => items.push(f));
      }
    });

    // 应用过滤/重命名/排序
    let filtered = filterItemsByParams(items, params);
    filtered = applyRename(filtered, params);
    filtered = applySort(filtered, params);

    // 最后输出 qx 行，一行一个节点
    return filtered.map(i => i.qx).join('\n');
  }

  function processFilterRules(resourceText, params) {
    // resourceText 通常是规则文件，按行转换
    // 同样先尝试 base64 解包
    let text = resourceText;
    const tryDec = tryBase64DecodeIfLooksLike(resourceText.replace(/\s+/g, ''));
    if (tryDec && tryDec.indexOf(',') !== -1) text = tryDec;
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l && !/^\s*(#|;|\/\/)/.test(l));
    // convert
    let items = lines.map((l, idx) => {
      const conv = convertRuleLine(l) || l;
      return { full: conv, name: conv, raw: l };
    });
    // filter
    items = filterItemsByParams(items, params);
    // rename (对规则名的 rename 通常没意义，但尝试替换 full 内容中的关键词)
    if (params.rename) {
      const ops = params.rename.split('+').map(s => s.trim()).filter(Boolean);
      items = items.map(it => {
        let f = it.full;
        ops.forEach(op => {
          const [oldStr, newStr] = splitOnce(op, '@');
          if (newStr !== undefined && oldStr) {
            try { f = f.replace(new RegExp(oldStr, 'g'), newStr); } catch(e) { f = f.split(oldStr).join(newStr); }
          } else if (op.startsWith('@')) {
            f = f + op.slice(1);
          } else if (op.endsWith('@')) {
            f = op.slice(0, -1) + f;
          }
        });
        return { ...it, full: f };
      });
    }
    // sort
    items = applySort(items, params);

    // 如果有 policy 参数，尝试在每条规则后追加 ",policy=NAME"（注意：Quantumult X 的规则语法对附加字段接受度会受版本影响）
    if (params.policy) {
      items = items.map(it => {
        if (it.full.indexOf(',policy=') === -1) return { ...it, full: it.full + `,policy=${params.policy}` };
        return it;
      });
    }
    return items.map(it => it.full).join('\n');
  }

  // ----------- entrypoint -----------
  function isNodeResource(text) {
    return /vmess:\/\//i.test(text) || /ssr?:\/\//i.test(text) || /trojan:\/\//i.test(text) || /shadowsocks=|vmess=|trojan=/i.test(text);
  }
  function isFilterResource(url, text) {
    // 如果文件名是 .list/.rule/.txt 或包含常见规则关键字，判定为规则文件
    if (/(\.list|\.rule|filter|rules|rule|acl)\b/i.test(url)) return true;
    // 判定内容是否多为以逗号分隔的规则行
    const sample = text.split(/\r?\n/).slice(0,50).join('\n');
    if (/(DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|FINAL|GEOIP|REGEX|URL-REGEX)/i.test(sample)) return true;
    // fallback: if many lines include commas and not protocol prefixes, treat as rules
    const lines = text.split(/\r?\n/).filter(Boolean);
    const commaLines = lines.filter(l => l.indexOf(',') !== -1).length;
    if (commaLines / Math.max(1, lines.length) > 0.5) return true;
    return false;
  }

  function main(url, resourceText) {
    // url 可能包含参数 #in=...&out=...
    const [baseUrl, paramString] = url.split('#');
    const params = parseParams(paramString || '');
    // decide type
    if (isNodeResource(resourceText)) {
      return processNodes(resourceText, params);
    } else if (isFilterResource(baseUrl || '', resourceText)) {
      return processFilterRules(resourceText, params);
    } else {
      // 尝试两者处理：先节点再规则（取决于实际内容）
      if (/vmess:\/\//i.test(resourceText) || /ssr?:\/\//i.test(resourceText) || /ss:\/\//i.test(resourceText)) {
        return processNodes(resourceText, params);
      }
      if (/(DOMAIN-SUFFIX|IP-CIDR|FINAL|host-suffix|host-keyword)/i.test(resourceText)) {
        return processFilterRules(resourceText, params);
      }
      // fallback: 原样返回
      return resourceText;
    }
  }

  return { parse: main };
})();
