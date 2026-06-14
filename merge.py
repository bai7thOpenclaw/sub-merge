import base64
import requests
import json
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= 从外部文件 sources.txt 读取订阅地址 =================
SOURCES_FILE = "sources.txt"

def load_subscription_urls():
    """读取 sources.txt，返回非空、非 # 开头的行列表"""
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

CHECK_TIMEOUT = 2          # TCP + TLS 握手超时（秒）
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
    """TCP 连接测试，如果端口是 443 则额外进行 TLS 握手"""
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

    merged_text = "\n".join(valid_lines)
    merged_b64 = base64.b64encode(merged_text.encode()).decode()
    return merged_b64, len(valid_lines)

if __name__ == "__main__":
    b64_sub, count = merge_subscriptions(SUBSCRIPTION_URLS)
    with open("merged_sub.txt", "w") as f:
        f.write(b64_sub)
    print(f"🎉 最终有效节点 {count} 条，已保存到 merged_sub.txt")