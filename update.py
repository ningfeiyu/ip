#!/usr/bin/env python3
import asyncio, os, shutil, subprocess, sys, time, urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from tqdm import tqdm

def _env_int(name, default):
    """空字符串回落到默认值（修复空环境变量直接崩溃）；非法值警告后用默认值。"""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"⚠️ 环境变量 {name} 值非法，已用默认值 {default}", file=sys.stderr)
        return default

def _env_float(name, default):
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        print(f"⚠️ 环境变量 {name} 值非法，已用默认值 {default}", file=sys.stderr)
        return default

def _env_bool(name, default=False):
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")

# --- 核心：从环境变量加载所有精细化参数 ---
# 延迟测试配置
TCP_WORKERS = _env_int("TCP_WORKERS", 400)
TCP_TIMEOUT = _env_float("TCP_TIMEOUT", 1.5)

# 测速引擎配置
SPEED_WORKERS = _env_int("SPEED_WORKERS", 12)
SPEED_TIMEOUT = _env_float("SPEED_TIMEOUT", 6.0)
# 引入缓冲区参数，默认为 16.0 秒
SPEED_PROCESS_BUFFER = _env_float("SPEED_PROCESS_BUFFER", 16.0)
SPEED_MIN_MBPS = _env_float("SPEED_MIN", 8.0)
# 达标优选最少条数：低于该数不覆盖旧结果并以退出码 2 失败（防空订阅）
MIN_BEST_COUNT = _env_int("MIN_BEST_COUNT", 5)
# 证书校验开关：默认开启校验（去掉 --insecure）。仅当节点是反代/ProxyIP、
# 其证书与 speed.cloudflare.com 不匹配时，才可把 SPEED_INSECURE 设为 true，
# 此时测速结果未经证书校验，不能证明是 Cloudflare 直连 IP。
SPEED_INSECURE = _env_bool("SPEED_INSECURE", False)

# 数量控制
MAX_NODES = _env_int("MAX_NODES", 1000000) # 默认全量
TOP_PER_REGION = _env_int("TOP_PER_REGION", 10)
MAX_LATENCY = _env_float("MAX_LATENCY", 0)  # 延迟上限(ms)，0=不限制

# 资源与文件配置
DOWNLOAD_TIMEOUT = _env_float("DOWNLOAD_TIMEOUT", 60.0)
INPUT_URL = os.getenv("INPUT_URL")
if not INPUT_URL:
    print("❌ 严重错误: 检测到 .env 配置失效或缺少 INPUT_URL！", file=sys.stderr)
    print("💡 为了防止运行偏离预期，程序已自动终止。", file=sys.stderr)
    sys.exit(1)

# === 【唯一新增的容错逻辑】 ===
# 如果老哥手快少写了协议头，自动在这里原地补齐，确保 urllib 能够解析
if "://" not in INPUT_URL:
    INPUT_URL = f"http://{INPUT_URL}"
# ==============================

# 文件名
INPUT_FILE = Path("ips.txt")
BEST_OUTPUT = Path("best_ips.txt")
FULL_OUTPUT = Path("full_ips.txt")

# 测速节点固定参数
SPEED_DOMAIN = "speed.cloudflare.com"
SPEED_PATH = "/__down"
SPEED_BYTES = 2 * 1024 * 1024
FAST_LABEL = "优选高速 "

@dataclass(frozen=True)
class Node:
    ip: str; port: int; region: str
    @property
    def raw(self) -> str: return f"{self.ip}:{self.port}#{self.region}"

def refresh_ips():
    """返回 (下载成功, 是否用了本地缓存)。来源失败不再静默：会明确打印警告。"""
    print(f"IP 来源: {INPUT_URL}")
    try:
        req = urllib.request.Request(INPUT_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            if resp.status == 200:
                INPUT_FILE.write_bytes(resp.read())
                return True, False
            print(f"⚠️ IP 来源返回 HTTP {resp.status}，未更新 ips.txt", file=sys.stderr)
    except Exception as exc:
        print(f"⚠️ IP 来源下载失败：{exc}", file=sys.stderr)
    if INPUT_FILE.exists():
        mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(INPUT_FILE.stat().st_mtime))
        print(f"⚠️ 使用本地缓存 ips.txt（最后修改 {mtime}），本次结果不是新鲜数据", file=sys.stderr)
        return False, True
    return False, False

def load_nodes():
    nodes, seen_ip_port = [], set()
    if not INPUT_FILE.exists(): return []
    for line in INPUT_FILE.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or "#" not in line: continue
        try:
            addr, reg = line.split("#", 1)
            ip, port = addr.rsplit(":", 1)
            n = Node(ip.strip(), int(port), reg.strip())
            # 按 IP:端口去重（同一 IP 不同端口才分别测速，同 IP:端口不再重复）
            if (n.ip, n.port) not in seen_ip_port:
                seen_ip_port.add((n.ip, n.port)); nodes.append(n)
        except Exception: continue
    return nodes[:MAX_NODES]

async def tcping(node: Node):
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(node.ip, node.port), timeout=TCP_TIMEOUT)
        writer.close(); await writer.wait_closed()
        return round((time.perf_counter() - start) * 1000, 2)
    except Exception: return None

def measure_speed(node: Node):
    curl = shutil.which("curl") or shutil.which("curl.exe")
    if curl is None:
        raise RuntimeError("未找到 curl，无法测速（不再静默记为 0 Mbps）")
    url = f"https://{SPEED_DOMAIN}:{node.port}{SPEED_PATH}?bytes={SPEED_BYTES}"
    # 列表形式参数，不用 shell=True；默认不加 --insecure，恢复证书校验。
    # 仅 SPEED_INSECURE=true 时才加 --insecure（反代/ProxyIP 场景），并已在启动时警告。
    cmd = [curl, "-s", "-o", "/dev/null", "-w", "%{size_download} %{time_total}",
           "--resolve", f"{SPEED_DOMAIN}:{node.port}:{node.ip}",
           "--connect-timeout", "3", "--max-time", str(SPEED_TIMEOUT)]
    if SPEED_INSECURE:
        cmd.append("--insecure")
    cmd.append(url)
    try:
        # 使用 SPEED_TIMEOUT + SPEED_PROCESS_BUFFER 作为进程级的物理死线
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=SPEED_TIMEOUT + SPEED_PROCESS_BUFFER)
        size, t = res.stdout.strip().split()
        return round((float(size) * 8) / (float(t) * 1_000_000), 2)
    except (subprocess.SubprocessError, OSError, ValueError):
        # 只捕获测速本身的失败（超时、进程错误、输出解析失败），不再吞掉所有异常。
        return 0.0

async def main():
    start_time = time.time()
    if shutil.which("curl") is None and shutil.which("curl.exe") is None:
        print("❌ 未找到 curl，测速无法进行，已终止（未覆盖旧结果）", file=sys.stderr)
        sys.exit(2)
    if SPEED_INSECURE:
        print("⚠️ SPEED_INSECURE=true：测速跳过证书校验，结果未经验证，不能证明是 Cloudflare 直连 IP（可能为反代/ProxyIP）", file=sys.stderr)
    fresh, used_cache = refresh_ips()
    if not fresh and not used_cache:
        print("❌ 无法获取 IP 列表且无本地缓存", file=sys.stderr)
        sys.exit(1)

    nodes = load_nodes()
    if not nodes:
        # 在任何写文件之前退出：此前这里会先截断 best/full 再除零崩溃，丢掉旧数据。
        print("❌ 节点列表为空（来源为空/HTML 错误页/全部解析失败），已终止，未覆盖旧结果", file=sys.stderr)
        sys.exit(1)
    total_nodes = len(nodes)
    print(f"🚀 参数就绪：并发{TCP_WORKERS}, 最高延迟{TCP_TIMEOUT}s, 目标{total_nodes}个")

    # 1. TCP 延迟测试
    tcp_results = []
    pbar = tqdm(total=total_nodes, desc="TCP 延迟测试")
    sem = asyncio.Semaphore(TCP_WORKERS)
    async def task(n):
        async with sem:
            lat = await tcping(n)
            if lat: tcp_results.append((n, lat))
            pbar.update(1)
    await asyncio.gather(*(task(n) for n in nodes))
    pbar.close()

    # 2. 分组筛选
    if MAX_LATENCY > 0:
        tcp_results = [(n, lat) for n, lat in tcp_results if lat <= MAX_LATENCY]
    groups = defaultdict(list)
    for n, lat in tcp_results: groups[n.region].append((n, lat))
    candidates = []
    for reg in groups:
        candidates.extend(sorted(groups[reg], key=lambda x: x[1])[:TOP_PER_REGION])

    # 3. 速度测试
    print(f"📢 测速阶段：并发{SPEED_WORKERS}, 最低速度{SPEED_MIN_MBPS}Mbps, 目标{len(candidates)}个")
    speed_results = []
    pbar_s = tqdm(total=len(candidates), desc="下载速度测试")
    loop = asyncio.get_event_loop()
    sem_s = asyncio.Semaphore(SPEED_WORKERS)
    async def s_task(n, lat):
        async with sem_s:
            s = await loop.run_in_executor(None, measure_speed, n)
            speed_results.append((n, lat, s))
            pbar_s.update(1)
    await asyncio.gather(*(s_task(n, lat) for n, lat in candidates))
    pbar_s.close()

    # 4. 排序与结果写入（先在内存里算完，再原子写入，绝不先截断旧文件）
    # 排序：延迟升序、速度降序，相同则按 IP、端口确定顺序（结果可复现、可 diff）
    speed_results.sort(key=lambda x: (x[1], -x[2], x[0].ip, x[0].port))
    full_lines, best_lines = [], []
    fast_count = 0
    for n, lat, s in speed_results:
        is_fast = s >= SPEED_MIN_MBPS
        tag = FAST_LABEL if is_fast else ""
        line = f"{n.raw} [{tag}{lat}ms {s}Mbps]\n"
        full_lines.append(line)
        if is_fast:
            best_lines.append(line)
            fast_count += 1

    if fast_count < MIN_BEST_COUNT:
        # 熔断：达标数不足时保留旧结果、不写任何文件，非 0 退出让 auto.sh 熔断生效。
        print(f"❌ 达标 IP 仅 {fast_count} 条，低于最小保留数 {MIN_BEST_COUNT}，保留旧结果，未覆盖订阅", file=sys.stderr)
        sys.exit(2)

    # 两文件都先写临时文件，成功后再一起 replace（单个文件是原子的，成对失败不丢一半旧数据）
    full_text, best_text = "".join(full_lines), "".join(best_lines)
    for path, text in ((FULL_OUTPUT, full_text), (BEST_OUTPUT, best_text)):
        tmp = path.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
    FULL_OUTPUT.with_suffix(".tmp").replace(FULL_OUTPUT)
    BEST_OUTPUT.with_suffix(".tmp").replace(BEST_OUTPUT)

    duration = int(time.time() - start_time)
    print(f"✨ 优选任务完成！总耗时: {duration}s")
    print(f"🕐 结果生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📊 IP 总数: {total_nodes}")
    print(f"✅ TCP 存活: {len(tcp_results)} ({round(len(tcp_results)/max(total_nodes, 1)*100, 1)}%)")
    print(f"⚡ 测速候选: {len(candidates)}")
    print(f"🏆 达标优选: {fast_count}")
    print("⭕ 结果已更新")

if __name__ == "__main__":
    asyncio.run(main())
