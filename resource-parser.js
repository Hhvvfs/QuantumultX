function Rule_Handle(subs, Pout = [], Pin = []) {
  subs = subs.map(item => item.trim()).filter(Boolean);
  let nlist = [];
  let Rk = ["//", ";", "^http"]; // Skip comments and HTTP rules if not handled
  subs.forEach(rule => {
    if (!Rk.some(key => rule.indexOf(key) != -1) && rule != "" && rule != "[Rule]") {
      let aftr = RuleQX(rule, Pout, Pin);
      if (aftr && aftr !== "[]") nlist.push(aftr);
    }
  });
  return nlist.join("\n");
}

function RuleQX(str, Pout, Pin) {
  let type = str.indexOf("DOMAIN-SET") !== -1 ? "set" : "rule";
  if (type === "rule") {
    return QXRule(str, Pout, Pin);
  } else if (type === "set") {
    return QXSet(str, Pout, Pin);
  }
  return "";
}

function QXRule(str, Pout, Pin) {
  let res = "";
  // Handle Loon/Surge common formats
  if (str.indexOf("IP-CIDR") !== -1 || str.indexOf("GEOIP") !== -1) {
    let parts = str.split(",");
    res = `ip-cidr, ${parts[1].trim()}, Proxy`;
  } else if (str.indexOf("DOMAIN-SUFFIX") !== -1) {
    let parts = str.split(",");
    res = `domain-suffix, ${parts[1].trim()}, Proxy`;
  } else if (str.indexOf("DOMAIN-KEYWORD") !== -1) {
    let parts = str.split(",");
    res = `domain-keyword, ${parts[1].trim()}, Proxy`;
  } else if (str.indexOf("DOMAIN") !== -1) {
    let parts = str.split(",");
    res = `domain, ${parts[1].trim()}, Proxy`;
  } else if (str.indexOf("HOST") !== -1) { // Loon specific: HOST
    let parts = str.split(",");
    res = `host, ${parts[1].trim()}, Proxy`;
  } else if (str.indexOf("^http") === 0) { // Loon HTTP rule
    let url = str.replace("^", "").trim();
    res = `url regex, ${url}, REJECT`; // Simplified conversion
  }

  // Apply filter (Pout: exclude, Pin: include)
  if (res) {
    let ruleMatch = res.split(",")[1].trim();
    if (Pout.length && Pout.some(out => ruleMatch.includes(out))) return "";
    if (Pin.length && !Pin.some(in_ => ruleMatch.includes(in_))) return "";
  }
  return res;
}

function QXSet(str, Pout, Pin) {
  let domains = str.split("\n").filter(Boolean); // Assuming multi-line domain-set
  let filtered = domains
    .map(domain => `domain, ${domain.trim()}, Proxy`)
    .filter(rule => {
      let ruleMatch = rule.split(",")[1].trim();
      if (Pout.length && Pout.some(out => ruleMatch.includes(out))) return false;
      if (Pin.length && !Pin.some(in_ => ruleMatch.includes(in_))) return false;
      return true;
    });
  return filtered.join("\n");
}
