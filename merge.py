import base64
import requests
import json
import socket
import ssl
import yaml
from urllib.parse import parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= 从外部文件 sources.txt 读取订阅地址 =================
SOURCES_FILE = "sources.txt"

def load_subscription_urls():
    urls = []
    try:
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    except FileNotFoundError:
        print(f"⚠️ 未找到 {SOURCES_FILE} 文件，请确保该文件存在于仓库根目录")
    return urls

SUBSCRIPTION_URLS = load_subscription_urls()
if not SUBSCRIPTION_URLS:
    raise RuntimeError(f"没有有效的订阅源，请检查 {SOURCES_FILE} 文件内容")
# ====================================================================

CHECK_TIMEOUT = 5
MAX_WORKERS = 50

def tcp_check(host, port):
    try:
        ip = socket.gethostbyname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CHECK_TIMEOUT)
        sock.connect((ip, port))
        sock.close()
        return True
    except:
        return False

def is_proxy_alive(proxy_obj):
    server = proxy_obj.get('server')
    port = proxy_obj.get('port')
    if not server or not port:
        return False
    try:
        port = int(port)
    except:
        return False
    return tcp_check(server, port)

def parse_subscription_content(content, url):
    proxies = []
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        if any(decoded.startswith(p) for p in ['vmess://', 'trojan://', 'vless://', 'ss://', 'hysteria2://']):
            lines = decoded.splitlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    proxy = convert_url_to_clash(line)
                    if proxy:
                        proxies.append(proxy)
            if proxies:
                print(f"✅ 从 {url} 解析到 {len(proxies)} 条节点（Base64格式）")
                return proxies
    except:
        pass

    try:
        data = yaml.safe_load(content)
        if data and isinstance(data, dict) and 'proxies' in data:
            proxy_list = data['proxies']
            if isinstance(proxy_list, list):
                proxies = proxy_list
                print(f"✅ 从 {url} 解析到 {len(proxies)} 条节点（YAML格式）")
                return proxies
    except:
        pass

    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            proxy = convert_url_to_clash(line)
            if proxy:
                proxies.append(proxy)
    if proxies:
        print(f"✅ 从 {url} 解析到 {len(proxies)} 条节点（纯文本格式）")
    else:
        print(f"⚠️ 从 {url} 未解析到任何节点")
    return proxies

def convert_url_to_clash(proxy_line: str) -> dict:
    try:
        if proxy_line.startswith("vmess://"):
            b64 = proxy_line[8:]
            decoded = base64.b64decode(b64).decode('utf-8')
            cfg = json.loads(decoded)
            cipher = cfg.get("scy", "auto")
            if not cipher:
                cipher = "auto"
            network = cfg.get("net", "tcp")
            proxy = {
                "name": "",
                "type": "vmess",
                "server": cfg.get("add"),
                "port": int(cfg.get("port", 0)),
                "uuid": cfg.get("id"),
                "alterId": cfg.get("aid", 0),
                "cipher": cipher,
                "network": network,
                "tls": cfg.get("tls", "") == "tls",
                "skip-cert-verify": True,
                "udp": True
            }
            if network == "ws" and "path" in cfg:
                proxy["ws-opts"] = {"path": cfg.get("path", "/")}
            if network == "grpc" and "serviceName" in cfg:
                proxy["grpc-opts"] = {"grpc-service-name": cfg.get("serviceName")}
            proxy = {k: v for k, v in proxy.items() if v is not None}
            return proxy

        elif proxy_line.startswith("trojan://"):
            parts = proxy_line[9:].split('@')
            password = parts[0]
            host_port_part = parts[1].split('?')[0].split('#')[0]
            host, port = host_port_part.split(':')
            proxy = {
                "name": "",
                "type": "trojan",
                "server": host,
                "port": int(port),
                "password": password,
                "udp": True,
                "skip-cert-verify": True
            }
            if '?' in proxy_line:
                query = proxy_line.split('?')[1].split('#')[0]
                params = parse_qs(query)
                if 'sni' in params:
                    proxy['sni'] = params['sni'][0]
                if 'allowInsecure' in params and params['allowInsecure'][0] == '1':
                    proxy['skip-cert-verify'] = True
            return proxy

        elif proxy_line.startswith("vless://"):
            parts = proxy_line[8:].split('@')
            uuid = parts[0]
            host_part = parts[1].split('?')[0]
            host, port = host_part.split(':')
            query = proxy_line.split('?')[1].split('#')[0]
            params = parse_qs(query)
            proxy = {
                "name": "",
                "type": "vless",
                "server": host,
                "port": int(port),
                "uuid": uuid,
                "encryption": params.get("encryption", ["none"])[0],
                "flow": params.get("flow", [""])[0],
                "tls": "tls" in params.get("security", []),
                "skip-cert-verify": True,
                "udp": True
            }
            if 'sni' in params:
                proxy['sni'] = params['sni'][0]
            return proxy

        elif proxy_line.startswith("ss://"):
            content = proxy_line[5:]
            if '@' in content:
                method_pass, host_port = content.split('@')
                method, password = method_pass.split(':')
                host_port = host_port.split('#')[0].split('/')[0]
                host, port = host_port.split(':')
            else:
                decoded = base64.b64decode(content).decode('utf-8')
                method_pass, host_port = decoded.split('@')
                method, password = method_pass.split(':')
                host, port = host_port.split(':')
            proxy = {
                "name": "",
                "type": "ss",
                "server": host,
                "port": int(port),
                "cipher": method,
                "password": password,
                "udp": True
            }
            return proxy

        elif proxy_line.startswith("hysteria2://"):
            parts = proxy_line[12:].split('@')
            password = parts[0]
            host_port_part = parts[1].split('?')[0].split('#')[0]
            host, port = host_port_part.split(':')
            query = proxy_line.split('?')[1] if '?' in proxy_line else ''
            params = parse_qs(query) if query else {}
            proxy = {
                "name": "",
                "type": "hysteria2",
                "server": host,
                "port": int(port),
                "password": password,
                "sni": params.get("sni", [host])[0],
                "skip-cert-verify": params.get("insecure", ["false"])[0] == "true",
                "udp": True
            }
            return proxy
        else:
            return None
    except Exception:
        return None

def proxy_key(proxy):
    t = proxy.get('type')
    if t == 'vmess':
        return (proxy.get('server'), proxy.get('port'), proxy.get('uuid'))
    elif t == 'trojan':
        return (proxy.get('server'), proxy.get('port'), proxy.get('password'))
    elif t == 'vless':
        return (proxy.get('server'), proxy.get('port'), proxy.get('uuid'))
    elif t == 'ss':
        return (proxy.get('server'), proxy.get('port'), proxy.get('password'))
    elif t == 'hysteria2':
        return (proxy.get('server'), proxy.get('port'), proxy.get('password'))
    else:
        return (proxy.get('server'), proxy.get('port'), t)

def deduplicate_proxies(proxies):
    seen = set()
    unique = []
    for p in proxies:
        key = proxy_key(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique

def merge_subscriptions(urls):
    all_proxies = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                print(f"❌ {url} 返回 {resp.status_code}")
                continue
            content = resp.text.strip()
            if not content:
                continue
            proxies = parse_subscription_content(content, url)
            if proxies:
                all_proxies.extend(proxies)
        except Exception as e:
            print(f"⚠️ 处理 {url} 时出错: {e}")

    all_proxies = deduplicate_proxies(all_proxies)
    print(f"📦 合并去重后共 {len(all_proxies)} 条节点，开始健康检查...")

    valid_proxies = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proxy = {executor.submit(is_proxy_alive, p): p for p in all_proxies}
        for i, future in enumerate(as_completed(future_to_proxy), 1):
            proxy = future_to_proxy[future]
            try:
                if future.result():
                    valid_proxies.append(proxy)
            except:
                pass
            if i % 50 == 0:
                print(f"  已检查 {i}/{len(all_proxies)} 个节点...")

    print(f"🎯 健康检查完成，有效节点 {len(valid_proxies)} 条（共 {len(all_proxies)} 条）")

    for idx, p in enumerate(valid_proxies, 1):
        p['name'] = f"node_{idx}"

    proxy_names = [p["name"] for p in valid_proxies]

    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": valid_proxies,
        "proxy-groups": [
            {
                "name": "🚀 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 150,
                "proxies": proxy_names
            },
            {
                "name": "🌍 手动选择",
                "type": "select",
                "proxies": proxy_names
            }
        ],
        "rule-providers": {
            "reject": {
                "type": "http",
                "behavior": "domain",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
                "path": "./ruleset/reject.yaml",
                "interval": 86400
            },
            "proxy": {
                "type": "http",
                "behavior": "domain",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
                "path": "./ruleset/proxy.yaml",
                "interval": 86400
            },
            "direct": {
                "type": "http",
                "behavior": "domain",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
                "path": "./ruleset/direct.yaml",
                "interval": 86400
            },
            "private": {
                "type": "http",
                "behavior": "domain",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
                "path": "./ruleset/private.yaml",
                "interval": 86400
            },
            "apple": {
                "type": "http",
                "behavior": "domain",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt",
                "path": "./ruleset/apple.yaml",
                "interval": 86400
            },
            "lancidr": {
                "type": "http",
                "behavior": "ipcidr",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
                "path": "./ruleset/lancidr.yaml",
                "interval": 86400
            },
            "cncidr": {
                "type": "http",
                "behavior": "ipcidr",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
                "path": "./ruleset/cncidr.yaml",
                "interval": 86400
            },
            "telegramcidr": {
                "type": "http",
                "behavior": "ipcidr",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
                "path": "./ruleset/telegramcidr.yaml",
                "interval": 86400
            }
        },
        # ========== 修正：将 PROXY 改为现有策略组 "🚀 自动选择" ==========
        "rules": [
            "RULE-SET,private,DIRECT",
            "RULE-SET,reject,REJECT",
            "RULE-SET,apple,DIRECT",
            "RULE-SET,direct,DIRECT",
            "RULE-SET,proxy,🚀 自动选择",          # 原为 PROXY
            "RULE-SET,cncidr,DIRECT",
            "RULE-SET,telegramcidr,🚀 自动选择",   # 原为 PROXY
            "RULE-SET,lancidr,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 自动选择"                    # 原为 PROXY
        ],
        "geodata": {
            "mode": True,
            "url": {
                "geoip": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
                "geosite": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
            },
            "auto-update": True,
            "update-interval": 24
        }
    }

    with open("merged_clash.yml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Clash 配置文件已生成: merged_clash.yml (含 {len(valid_proxies)} 条有效节点，内置规则集)")

    base64_lines = [f"{p.get('server', 'unknown')}:{p.get('port', 'unknown')}" for p in valid_proxies]
    base64_content = "\n".join(base64_lines)
    base64_encoded = base64.b64encode(base64_content.encode()).decode()
    with open("merged_sub.txt", "w") as f:
        f.write(base64_encoded)
    print(f"📁 同时生成了 Base64 格式订阅 merged_sub.txt")

    return base64_encoded, len(valid_proxies)

if __name__ == "__main__":
    b64_sub, count = merge_subscriptions(SUBSCRIPTION_URLS)