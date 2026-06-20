import base64
import requests
import json
import socket
import ssl
import yaml
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

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

CHECK_TIMEOUT = 5          # TCP 握手超时（秒）
MAX_WORKERS = 50           # 并发线程数

# ---------- 健康检查函数（修改为仅 TCP 握手） ----------
def tcp_check(host, port):
    """仅做 TCP 连接测试，不做 TLS 握手（避免误判）"""
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
    """从代理对象中提取 server 和 port 进行健康检查"""
    server = proxy_obj.get('server')
    port = proxy_obj.get('port')
    if not server or not port:
        return False
    try:
        port = int(port)
    except:
        return False
    return tcp_check(server, port)

# ---------- 解析订阅内容 ----------
def parse_subscription_content(content, url):
    """
    尝试解析订阅内容，返回代理对象列表（字典）
    支持格式：
      - Base64 编码的节点 URL 列表（每行一个 vmess:// 等）
      - 纯文本节点 URL 列表
      - YAML 格式的 Clash 配置（提取 proxies 字段）
    """
    proxies = []

    # 1. 尝试 Base64 解码
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        # 检查解码后是否包含常见的代理 URL 前缀
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

    # 2. 尝试 YAML 解析
    try:
        data = yaml.safe_load(content)
        if data and isinstance(data, dict) and 'proxies' in data:
            proxy_list = data['proxies']
            if isinstance(proxy_list, list):
                # 直接使用原始代理对象（保留所有字段）
                proxies = proxy_list
                print(f"✅ 从 {url} 解析到 {len(proxies)} 条节点（YAML格式）")
                return proxies
    except:
        pass

    # 3. 按行解析（认为是 URL 列表）
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

# ---------- URL 转 Clash 代理对象 ----------
def convert_url_to_clash(proxy_line: str) -> dict:
    """将 vmess:// / trojan:// / vless:// / ss:// / hysteria2:// 转换为 Clash 代理对象"""
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
            # 处理 ws 等额外选项（如果有）
            if network == "ws" and "path" in cfg:
                proxy["ws-opts"] = {"path": cfg.get("path", "/")}
            if network == "grpc" and "serviceName" in cfg:
                proxy["grpc-opts"] = {"grpc-service-name": cfg.get("serviceName")}
            # 去除可能为 None 的字段
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
    except Exception as e:
        return None

# ---------- 去重函数 ----------
def proxy_key(proxy):
    """生成代理对象的唯一键（基于 server, port, type, 以及关键凭证）"""
    if proxy.get('type') == 'vmess':
        return (proxy.get('server'), proxy.get('port'), proxy.get('uuid'))
    elif proxy.get('type') == 'trojan':
        return (proxy.get('server'), proxy.get('port'), proxy.get('password'))
    elif proxy.get('type') == 'vless':
        return (proxy.get('server'), proxy.get('port'), proxy.get('uuid'))
    elif proxy.get('type') == 'ss':
        return (proxy.get('server'), proxy.get('port'), proxy.get('password'))
    elif proxy.get('type') == 'hysteria2':
        return (proxy.get('server'), proxy.get('port'), proxy.get('password'))
    else:
        return (proxy.get('server'), proxy.get('port'), proxy.get('type'))

def deduplicate_proxies(proxies):
    seen = set()
    unique = []
    for p in proxies:
        key = proxy_key(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique

# ---------- 主合并函数 ----------
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

    if not valid_proxies:
        print("⚠️ 没有有效节点，生成空配置")
        clash_config = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "info",
            "external-controller": "127.0.0.1:9090",
            "proxies": [],
            "proxy-groups": [],
            "rules": ["MATCH,DIRECT"]
        }
    else:
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
            "rules": [
                "MATCH,🚀 自动选择"
            ]
        }

    with open("merged_clash.yml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Clash 配置文件已生成: merged_clash.yml (含 {len(valid_proxies)} 条有效节点)")

    base64_lines = []
    for p in valid_proxies:
        base64_lines.append(f"{p.get('server', 'unknown')}:{p.get('port', 'unknown')}")
    base64_content = "\n".join(base64_lines)
    base64_encoded = base64.b64encode(base64_content.encode()).decode()
    with open("merged_sub.txt", "w") as f:
        f.write(base64_encoded)
    print(f"📁 同时生成了 Base64 格式订阅 merged_sub.txt")

    return base64_encoded, len(valid_proxies)

if __name__ == "__main__":
    b64_sub, count = merge_subscriptions(SUBSCRIPTION_URLS)