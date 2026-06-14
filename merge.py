import base64
import requests
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= 10 个订阅地址（全部来自 GitHub 公开项目） =================
SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/74647/Proxify/main/Sub/Base64.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_list.txt",
    "https://raw.githubusercontent.com/erfanrashti/proxy_collector/main/sub/proxies.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/sub.txt",
    "https://raw.githubusercontent.com/zhuifengshen/xray-collector/main/sub/sub.txt",
    "https://raw.githubusercontent.com/Elahe-dastan/proxy_scraper/main/sub/proxies.txt",
]

CHECK_TIMEOUT = 3          # TCP 超时（秒）
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
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
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