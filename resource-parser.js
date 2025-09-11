/**
 * Quantumult X 简化版资源解析器
 * 功能：节点解析 + 分流规则解析
 * 参数支持：in / out / regex / rename / sort / policy
 */

(function() {
  function parseParams(paramString) {
    const params = {};
    paramString.split('&').forEach(kv => {
      const [k, v] = kv.split('=');
      if (k && v !== undefined) {
        params[k] = decodeURIComponent(v);
      }
    });
    return params;
  }

  function matchesKeyword(name, keywords) {
    return keywords.split('+').some(kw => name.includes(kw));
  }

  function filterItems(items, params) {
    return items.filter(item => {
      if (params.in && !matchesKeyword(item.name, params.in)) return false;
      if (params.out && matchesKeyword(item.name, params.out)) return false;
      if (params.regex) {
        const re = new RegExp(params.regex);
        if (!re.test(item.full)) return false;
      }
      return true;
    });
  }

  function renameItem(item, params) {
    if (!params.rename) return item;
    params.rename.split('+').forEach(pair => {
      const [oldStr, newStr] = pair.split('@');
      if (oldStr && newStr !== undefined) {
        item.name = item.name.replace(new RegExp(oldStr, 'g'), newStr);
      } else if (oldStr && newStr === undefined) {
        if (pair.startsWith('@')) {
          item.name = item.name + pair.substring(1);
        } else if (pair.endsWith('@')) {
          item.name = pair.substring(0, pair.length - 1) + item.name;
        }
      }
    });
    return item;
  }

  function sortItems(items, params) {
    if (!params.sort) return items;
    if (params.sort === '1') {
      return items.sort((a, b) => a.name.localeCompare(b.name));
    } else if (params.sort === '-1') {
      return items.sort((a, b) => b.name.localeCompare(a.name));
    } else if (params.sort.toLowerCase() === 'x') {
      return items.sort(() => Math.random() - 0.5);
    }
    return items;
  }

  function processNodes(resourceText, params) {
    const lines = resourceText.split('\n').filter(l => l.trim());
    let items = lines.map((line, idx) => ({
      full: line,
      name: extractNameFromLine(line) || `Node-${idx+1}`
    }));
    items = filterItems(items, params).map(item => renameItem(item, params));
    items = sortItems(items, params);
    return items.map(item => item.full).join('\n');
  }

  function processFilterRules(resourceText, params) {
    const lines = resourceText.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
    let items = lines.map((line, idx) => ({
      full: line,
      name: extractTagOrIdentifier(line) || `Rule-${idx+1}`
    }));
    items = filterItems(items, params).map(item => renameItem(item, params));
    items = sortItems(items, params);
    if (params.policy) {
      items = items.map(item => {
        if (!item.full.includes(',policy=')) {
          return { ...item, full: item.full + `,policy=${params.policy}` };
        }
        return item;
      });
    }
    return items.map(item => item.full).join('\n');
  }

  function main(url, resourceText) {
    const [baseUrl, paramString] = url.split('#');
    const params = paramString ? parseParams(paramString) : {};
    if (isNodeResource(resourceText)) {
      return processNodes(resourceText, params);
    } else if (isFilterResource(baseUrl, resourceText)) {
      return processFilterRules(resourceText, params);
    } else {
      return resourceText;
    }
  }

  function isNodeResource(text) {
    return /vmess:\/\//.test(text) || /ssr?:\/\//.test(text) || /trojan:\/\//.test(text);
  }

  function isFilterResource(url, text) {
    return url.endsWith('.list') || /,policy=/.test(text) || /^HOST,/.test(text.trim());
  }

  function extractNameFromLine(line) {
    // 这里可以写更细的解析逻辑，比如解析 vmess 里的 ps 字段
    const remark = line.match(/remarks?=([^&]+)/i);
    if (remark) return remark[1];
    return null;
  }

  function extractTagOrIdentifier(line) {
    const m = line.match(/tag=([^,]+)/);
    if (m) return m[1];
    return null;
  }

  return { parse: main };
})();
