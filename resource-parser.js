/*
Quantumult X Resource Parser
by Community (Simplified by Grok)
Support: Subscription links (VMess, Trojan, VLESS, SS/SSR) and Divert Rules (Surge/Clash to QX)
Usage: Add to [general] section: resource_parser_url = https://your-host/resource-parser.js
*/

const isQX = typeof $task !== "undefined";

const url = $request.url;
const body = $request.body || $response.body;

if (!body) {
  console.log("No body found");
  $done({});
}

let input = body.trim();

// Detect and decode base64 if needed
if (input.match(/^[A-Za-z0-9+/=]+$/)) {
  try {
    input = atob(input);
  } catch (e) {
    console.log("Base64 decode error");
  }
}

// Function to parse subscription links (nodes)
function parseSubscription(data) {
  let nodes = [];
  if (data.includes("vmess://") || data.includes("trojan://") || data.includes("vless://")) {
    const lines = data.split("\n").filter(line => line.trim());
    lines.forEach(line => {
      if (line.startsWith("vmess://")) {
        let decoded = atob(line.replace("vmess://", ""));
        let vmess = JSON.parse(decoded);
        let qxNode = `vmess = ${vmess.add}:${vmess.port}, username=${vmess.id}, tls=${vmess.tls ? "true" : "false"}, ws=${vmess.net === "ws"}, ws-path=${vmess.path || "/"}, ws-headers=host:${vmess.host || vmess.add}`;
        nodes.push(qxNode);
      } else if (line.startsWith("trojan://")) {
        let parts = line.replace("trojan://", "").split("@");
        let auth = parts[0];
        let [host, port] = parts[1].split(":");
        let qxNode = `trojan = ${host}:${port}, password=${auth}, tls=true`;
        nodes.push(qxNode);
      } // Add more for VLESS, SS etc.
    });
    return nodes.join("\n");
  }
  return data; // Return original if not matched
}

// Function to parse divert rules (routing rules)
function parseRules(data) {
  let rules = [];
  const lines = data.split("\n").filter(line => line.trim() && !line.startsWith("#") && !line.startsWith(";"));
  lines.forEach(line => {
    if (line.includes("DOMAIN-SUFFIX") || line.includes("IP-CIDR")) { // Surge style
      let parts = line.split(",");
      let type = parts[0].trim();
      let value = parts[1].trim();
      let policy = parts[2] ? parts[2].trim() : "DIRECT";
      let qxRule = `${type},${value},${policy}`;
      rules.push(qxRule);
    } else if (data.includes("rules:") || data.includes("proxies:")) { // Clash YAML
      // Simple YAML to QX conversion (requires yaml parser, but simplified here)
      try {
        let yaml = JSON.parse(data.replace(/rules:/g, '"rules":').replace(/- /g, '"').replace(/,/g, '","')); // Rough parse
        yaml.rules.forEach(rule => {
          let qxRule = `${rule.type},${rule.value},${rule.policy || "PROXY"}`;
          rules.push(qxRule);
        });
      } catch (e) {
        console.log("YAML parse error");
      }
    }
  });
  return rules.join("\n");
}

// Main logic
let output;
if (url.includes("subscribe") || input.includes("://")) { // Assume subscription
  output = parseSubscription(input);
} else { // Assume rules
  output = parseRules(input);
}

if (output) {
  $done({ body: output });
} else {
  console.log("Parse failed");
  $done({});
}
