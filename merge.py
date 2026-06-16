import base64
import requests
import json
import socket
import ssl
import yaml
from urllib.parse import urlparse, parse_qs
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

CHECK_TIMEOUT = 5          # TCP + TLS 握手超时（秒）
MAX_WORKERS = 50           # 并发线程数

def extract_host_port(proxy_line: str):
    if proxy_line.startswith("vmess://"):
        try:
            b64 = proxy_line[8:]
            decoded = base64.b64decode(b64).decode('utf-8')
            config = json.loads(decoded)
            return config.get('add'), config.get('port')
        except:
            pass
    if proxy_line.startswith("trojan://"):
        try:
            at_pos = proxy_line.find('@')
            if at_pos != -1:
                host_part = proxy_line[at_pos+1:].split('?')[0].split('#')[0].split('/')[0]
                if ':' in host_part:
                    host, port = host_part.split(':')
                    return host, int(port)
        except:
            pass
    if proxy_line.startswith("vless://"):
        try:
            at_pos = proxy_line.find('@')
            if at_pos != -1:
                host_part = proxy_line[at_pos+1:].split('?')[0].split('#')[0].split('/')[0]
                if ':' in host_part:
                    host, port = host_part.split(':')
                    return host, int(port)
        except:
            pass
    if proxy_line.startswith("ss://"):
        try:
            at_pos = proxy_line.find('@')
            if at_pos != -1:
                host_part = proxy_line[at_pos+1:].split('?')[0].split('#')[0].split('/')[0]
                if ':' in host_part:
                    host, port = host_part.split(':')
                    return host, int(port)
            else:
                b64 = proxy_line[5:]
                decoded = base64.b64decode(b64).decode('utf-8')
                if '@' in decoded:
                    host_part = decoded.split('@')[1]
                    host, port = host_part.split(':')
                    return host, int(port)
        except:
            pass
    return None, None

def tcp_check(host, port):
    try:
        ip = socket.gethostbyname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CHECK_TIMEOUT)
        sock.connect((ip, port))

        if port == 443 or "tls" in str(host).lower():
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.getpeername()
        else:
            sock.close()
        return True
    except:
        return False

def check_proxy_line(proxy_line):
    host, port = extract_host_port(proxy_line)
    if host is None or port is None:
        return False
    return tcp_check(host, port)

# ================= 修改：转换函数，增加空值回退 =================
def convert_to_clash_proxy(proxy_line: str, index: int) -> dict:
    name = f"node_{index}"
    try:
        if proxy_line.startswith("vmess://"):
            b64 = proxy_line[8:]
            decoded = base64.b64decode(b64).decode('utf-8')
            cfg = json.loads(decoded)
            # 处理 cipher：如果不存在或为空，设为 "auto"
            cipher = cfg.get("scy", "auto")
            if not cipher:
                cipher = "auto"
            return {
                "name": cfg.get("ps", name),
                "type": "vmess",
                "server": cfg.get("add"),
                "port": int(cfg.get("port", 0)),
                "uuid": cfg.get("id"),
                "alterId": cfg.get("aid", 0),
                "cipher": cipher,
                "tls": cfg.get("tls", "") == "tls",
                "skip-cert-verify": True,
                "udp": True
            }
        elif proxy_line.startswith("trojan://"):
            parts = proxy_line[9:].split('@')
            password = parts[0]
            host_port_part = parts[1].split('?')[0].split('#')[0]
            host, port = host_port_part.split(':')
            return {
                "name": name,
                "type": "trojan",
                "server": host,
                "port": int(port),
                "password": password,
                "udp": True,
                "skip-cert-verify": True
            }
        elif proxy_line.startswith("vless://"):
            parts = proxy_line[8:].split('@')
            uuid = parts[0]
            host_part = parts[1].split('?')[0]
            host, port = host_part.split(':')
            query_str = proxy_line.split('?')[1].split('#')[0]
            params = parse_qs(query_str)
            return {
                "name": name,
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
            return {
                "name": name,
                "type": "ss",
                "server": host,
                "port": int(port),
                "cipher": method,
                "password": password,
                "udp": True
            }
    except Exception as e:
        print(f"⚠️ 转换节点 {name} 失败: {e}")
    return None

def merge_subscriptions(urls):
    merged_lines = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                print(f"❌ {url} 返回 {resp.status_code}")
                continue
            text = resp.text.strip()
            try:
                decoded = base64.b64decode(text).decode('utf-8')
                lines = decoded.splitlines()
            except:
                lines = text.splitlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    merged_lines.append(line)
            print(f"✅ 从 {url} 获取 {len(lines)} 条节点")
        except Exception as e:
            print(f"⚠️ 处理 {url} 时出错: {e}")

    merged_lines = list(dict.fromkeys(merged_lines))
    print(f"📦 合并去重后共 {len(merged_lines)} 条节点，开始健康检查...")

    valid_lines = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_line = {executor.submit(check_proxy_line, line): line for line in merged_lines}
        for i, future in enumerate(as_completed(future_to_line), 1):
            line = future_to_line[future]
            try:
                if future.result():
                    valid_lines.append(line)
            except:
                pass
            if i % 50 == 0:
                print(f"  已检查 {i}/{len(merged_lines)} 个节点...")

    print(f"🎯 健康检查完成，有效节点 {len(valid_lines)} 条（共 {len(merged_lines)} 条）")

    clash_proxies = []
    for idx, line in enumerate(valid_lines, start=1):
        proxy = convert_to_clash_proxy(line, idx)
        if proxy:
            clash_proxies.append(proxy)

    print(f"🔄 成功转换 {len(clash_proxies)} 条节点为 Clash 格式")

    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "🚀 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 150,
                "proxies": [p["name"] for p in clash_proxies]
            },
            {
                "name": "🌍 手动选择",
                "type": "select",
                "proxies": [p["name"] for p in clash_proxies]
            }
        ],
        "rules": [
            "MATCH,🚀 自动选择"
        ]
    }

    with open("merged_clash.yml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Clash 配置文件已生成: merged_clash.yml (含 {len(clash_proxies)} 条有效节点)")

    merged_text = "\n".join(valid_lines)
    merged_b64 = base64.b64encode(merged_text.encode()).decode()
    with open("merged_sub.txt", "w") as f:
        f.write(merged_b64)
    print(f"📁 同时生成了 Base64 格式订阅 merged_sub.txt")

    return merged_b64, len(valid_lines)

if __name__ == "__main__":
    b64_sub, count = merge_subscriptions(SUBSCRIPTION_URLS)
